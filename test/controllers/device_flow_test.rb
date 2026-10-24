# frozen_string_literal: true

require "test_helper"
require "action_controller"
require "rack/test"

# The device flow's two endpoints (RFC 8628 §3.1 to §3.5) as a host app's
# API controller serves them, through Rails' real request stack.
class DeviceFlowTest < ApiKeys::Test
  include Rack::Test::Methods

  GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"
  CLIENT = "Fictional agent"

  class DevicesController < ActionController::API
    include ApiKeys::DeviceFlow

    cattr_accessor :default_scope, :extra_response, :fail_in_response, :key_type_name

    private

    def device_verification_uri(user_code = nil)
      user_code ? "https://app.example.com/device?code=#{user_code}" : "https://app.example.com/device"
    end

    def device_default_scope
      default_scope
    end

    def device_key_type
      key_type_name || super
    end

    def device_token_response(authorization, api_key)
      raise "the response cannot be built" if fail_in_response

      extra_response ? super.merge(owner: { name: authorization.owner.name }) : super
    end
  end

  # A host that forgot to name its approval page.
  class UnnamedPageController < ActionController::API
    include ApiKeys::DeviceFlow
  end

  ROUTES = ActionDispatch::Routing::RouteSet.new.tap do |routes|
    routes.draw do
      post "/device", to: DevicesController.action(:create)
      post "/token", to: DevicesController.action(:token)
      post "/unnamed/device", to: UnnamedPageController.action(:create)
    end
  end

  def app
    ROUTES
  end

  def setup
    super
    ApiKeys.configure do |config|
      config.default_scopes = %w[read write]
      config.enable_async_operations = false
    end
    DevicesController.default_scope = nil
    DevicesController.extra_response = false
    DevicesController.fail_in_response = false
    DevicesController.key_type_name = nil
    @owner = User.create!(name: "Acme")
    @person = User.create!(name: "Ada")
  end

  def post_json(path, body, headers = {})
    post path, body.to_json, { "CONTENT_TYPE" => "application/json" }.merge(headers)
    JSON.parse(last_response.body)
  end

  def request_codes(**params)
    post_json "/device", { client_id: CLIENT, device_name: "build-box", scope: "read write" }.merge(params).compact
  end

  def poll(codes, client_id: CLIENT, grant_type: GRANT_TYPE)
    post_json "/token", { grant_type: grant_type, device_code: codes["device_code"], client_id: client_id }.compact
  end

  def approve(codes)
    ApiKeys::DeviceAuthorization.find_undecided_by_user_code(codes["user_code"]).approve!(@owner, by: @person)
  end

  test "the device authorization response has the fields of RFC 8628 §3.2, and no cache keeps it" do
    codes = request_codes

    assert_equal 200, last_response.status
    assert_equal %w[device_code expires_in interval user_code verification_uri verification_uri_complete], codes.keys.sort
    assert_match(/\A[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}\z/, codes["user_code"])
    assert_equal "https://app.example.com/device", codes["verification_uri"]
    assert_equal "https://app.example.com/device?code=#{codes['user_code']}", codes["verification_uri_complete"]
    assert_equal [600, 5], codes.values_at("expires_in", "interval")
    assert_equal "no-store", last_response.headers["Cache-Control"]
    assert_equal "no-cache", last_response.headers["Pragma"]

    authorization = ApiKeys::DeviceAuthorization.sole
    assert_equal CLIENT, authorization.client_id
    assert_equal "build-box", authorization.device_name
    assert_equal %w[read write], authorization.scopes
  end

  test "the request is recorded from the client IP the gem resolves" do
    ApiKeys.configure { |config| config.client_ip_resolver = ->(_request) { "198.51.100.9" } }
    request_codes

    assert_equal "198.51.100.9", ApiKeys::DeviceAuthorization.sole.requested_from
  end

  test "a form-encoded request works as OAuth clients send it (RFC 8628 §3.1)" do
    post "/device", { client_id: CLIENT, scope: "read" }

    assert_equal 200, last_response.status
    assert_equal %w[read], ApiKeys::DeviceAuthorization.sole.scopes
  end

  test "the whole flow: pending, approval, the token once, then invalid_grant" do
    codes = request_codes

    assert_equal "authorization_pending", poll(codes)["error"]
    assert_equal 400, last_response.status

    approve(codes)
    token = poll(codes)
    assert_equal 200, last_response.status
    assert_equal "no-store", last_response.headers["Cache-Control"]
    assert_equal({ "token_type" => "Bearer", "scope" => "read write" }, token.except("access_token"))
    key = @owner.api_keys.sole
    assert_equal "Fictional agent on build-box", key.name
    assert_equal key, ApiKeys::Services::Authenticator.call(
      Struct.new(:headers, :query_parameters, :protocol, :remote_ip).new(
        { "Authorization" => "Bearer #{token['access_token']}" }, {}, "https://", "203.0.113.7"
      )
    ).api_key

    assert_equal "invalid_grant", poll(codes)["error"], "the token comes once"
    assert_equal 1, @owner.api_keys.count
  end

  test "a poll from another client_id, or none, gets invalid_grant and leaves the grant to its client" do
    codes = request_codes
    approve(codes)

    ["Another agent", nil, ""].each do |client_id|
      assert_equal "invalid_grant", poll(codes, client_id: client_id)["error"], client_id.inspect
    end
    assert_empty @owner.api_keys

    poll(codes)
    assert_equal 200, last_response.status
  end

  test "polls too soon are told to slow down" do
    codes = request_codes
    poll(codes)

    assert_equal "slow_down", poll(codes)["error"]
    assert_equal 10, ApiKeys::DeviceAuthorization.sole.interval
  end

  test "a denied or expired request answers with its RFC 8628 §3.5 error" do
    denied = request_codes
    ApiKeys::DeviceAuthorization.find_undecided_by_user_code(denied["user_code"]).deny!(by: @person)
    assert_equal "access_denied", poll(denied)["error"]

    expired = request_codes
    travel ApiKeys::DeviceAuthorization::LIFETIME + 1.second do
      assert_equal "expired_token", poll(expired)["error"]
    end
  end

  test "the client's mistakes get the RFC's error codes and descriptions" do
    assert_equal "invalid_scope", request_codes(scope: "read admin")["error"]
    assert_equal "Ask for scopes among: read write.", JSON.parse(last_response.body)["error_description"]
    assert_equal "invalid_scope", request_codes(scope: "")["error"]
    assert_equal "invalid_request", request_codes(client_id: nil)["error"]
    assert_equal "invalid_request", request_codes(device_name: "x" * 61)["error"]
    assert_equal 400, last_response.status
    assert_equal "no-store", last_response.headers["Cache-Control"]

    assert_equal "unsupported_grant_type", poll({ "device_code" => "x" }, grant_type: "password")["error"]
    assert_equal "invalid_grant", poll({ "device_code" => "unknown" })["error"]
    assert_equal "invalid_grant", poll({})["error"]
    assert_match "client_id", JSON.parse(last_response.body)["error_description"]
    assert_empty ApiKeys::DeviceAuthorization.all
  end

  test "without a scope the request fails, unless the host names a default (RFC 6749 §3.3)" do
    assert_equal "invalid_scope", request_codes(scope: nil)["error"]
    assert_empty ApiKeys::DeviceAuthorization.all

    DevicesController.default_scope = "read"
    request_codes(scope: nil)
    assert_equal 200, last_response.status
    assert_equal %w[read], ApiKeys::DeviceAuthorization.sole.scopes
  end

  test "the host adds fields to the token response by calling super" do
    DevicesController.extra_response = true
    codes = request_codes
    approve(codes)

    token = poll(codes)
    assert_equal "Bearer", token["token_type"]
    assert_equal({ "name" => "Acme" }, token["owner"])
  end

  test "the token response is built in the transaction that creates the key: if it fails, no key is made" do
    DevicesController.fail_in_response = true
    codes = request_codes
    approve(codes)

    assert_raises(RuntimeError) { poll(codes) }
    assert_empty @owner.api_keys
    assert ApiKeys::DeviceAuthorization.sole.approved?, "the next poll can still get the key"

    DevicesController.fail_in_response = false
    poll(codes)
    assert_equal 200, last_response.status
    assert_equal 1, @owner.api_keys.count
  end

  test "error descriptions can be changed with I18n" do
    I18n.backend.store_translations(:en, api_keys: { device_flow: { errors: { invalid_scope: "Pick from %{scopes}" } } })

    assert_equal "Pick from read write", request_codes(scope: "admin")["error_description"]
  ensure
    I18n.reload!
  end

  test "with key types configured, the flow makes keys of the default type, or of the type the host names" do
    ApiKeys.configure do |config|
      config.key_types = { secret: { prefix: "sk", permissions: :all }, agent: { prefix: "ag", permissions: %w[read] } }
      config.default_key_type = :secret
    end

    request_codes(scope: "read write")
    assert_equal "secret", ApiKeys::DeviceAuthorization.last.key_type

    DevicesController.key_type_name = :agent
    assert_equal "invalid_scope", request_codes(scope: "read write")["error"]
    assert_equal "Ask for scopes among: read.", JSON.parse(last_response.body)["error_description"]
    codes = request_codes(scope: "read")
    approve(codes)
    poll(codes)
    assert_match(/\Aag_/, JSON.parse(last_response.body)["access_token"])
  end

  test "with key types configured and no type named, the request fails as the app's error, not the client's" do
    ApiKeys.configure { |config| config.key_types = { secret: { prefix: "sk", permissions: :all } } }

    error = assert_raises(ArgumentError) { request_codes }
    assert_match "device_key_type", error.message
    assert_empty ApiKeys::DeviceAuthorization.all
  end

  test "a ceiling type: a request for part of the ceiling is invalid_scope, and a widened ceiling stops the poll" do
    ApiKeys.configure do |config|
      config.key_types = { agent: { prefix: "ag", permissions: %w[read write], scopes: :ceiling } }
    end
    DevicesController.key_type_name = :agent

    assert_equal "invalid_scope", request_codes(scope: "read")["error"]
    codes = request_codes(scope: "read write")
    approve(codes)
    ApiKeys.configuration.key_types = { agent: { prefix: "ag", permissions: %w[read write admin], scopes: :ceiling } }

    refused = poll(codes)
    assert_equal "invalid_scope", refused["error"]
    assert_match "more than the person approved", refused["error_description"]
    assert_empty @owner.api_keys
  end

  test "a host must name its approval page" do
    error = assert_raises(NotImplementedError) do
      post_json "/unnamed/device", { client_id: CLIENT, scope: "read" }
    end
    assert_match "device_verification_uri", error.message
  end
end
