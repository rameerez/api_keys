# frozen_string_literal: true

require "test_helper"
require "active_job"

# config.on_key_refused: the host's hook for a refusal of an identified key,
# with the key, the code and the request. It runs after the refusal is
# rendered and recorded, and it can never change the refusal.
class OnKeyRefusedTest < ApiKeys::Test
  include ActiveJob::TestHelper

  class FakeRequest
    attr_reader :headers, :query_parameters, :protocol, :uuid, :remote_ip

    def initialize(token: nil, origin: nil, remote_ip: "203.0.113.7")
      @headers = {}
      @headers["Authorization"] = "Bearer #{token}" if token
      @headers["Origin"] = origin if origin
      @query_parameters = {}
      @protocol = "https://"
      @remote_ip = remote_ip
      @uuid = SecureRandom.uuid
    end
  end

  class FakeController
    include ApiKeys::Authentication

    attr_reader :rendered, :request

    def initialize(request)
      @request = request
      @rendered = nil
    end

    def render(json:, status:)
      @rendered = { json: json, status: status }
    end
  end

  # An app that overrode the private record_key_refusal before
  # on_key_refused existed, the way such apps did it.
  class OverridingController < FakeController
    attr_reader :overridden_calls

    def record_key_refusal(api_key, error_code)
      super
      (@overridden_calls ||= []) << [api_key.id, error_code]
    end
  end

  def setup
    super
    ApiKeys.configuration.enable_async_operations = true
    @user = User.create!(name: "Refused Owner")
    @calls = []
    calls = @calls
    ApiKeys.configuration.on_key_refused = ->(api_key:, error_code:, request:) do
      calls << { api_key: api_key, error_code: error_code, request: request }
    end
  end

  test "an origin refusal hands the hook the key, the code and the request" do
    key = @user.create_api_key!(name: "Widget", allowed_origins: "example.com")

    controller = authenticate(key.token, origin: "https://elsewhere.example")

    assert_equal :forbidden, controller.rendered[:status]
    assert_equal :origin_not_allowed, controller.rendered[:json][:error]
    assert_equal 1, @calls.length
    call = @calls.first
    assert_equal key.id, call[:api_key].id
    assert_equal :origin_not_allowed, call[:error_code]
    assert_same controller.request, call[:request]
    assert_equal "elsewhere.example", ApiKeys::Restrictions.extract_origin_host(call[:request])
  end

  test "it runs for refusals decided in the controller too: missing scope and untrusted key" do
    read_only = @user.create_api_key!(name: "Read Only", scopes: %w[read])
    authenticate(read_only.token, scope: "write")

    distrusted = @user.create_api_key!(name: "Distrusted")
    ApiKeys.configuration.trusted_key_check = ->(_api_key) { false }
    authenticate(distrusted.token)

    assert_equal [[read_only.id, :missing_scope], [distrusted.id, :untrusted_key]],
      @calls.map { |call| [call[:api_key].id, call[:error_code]] }
  end

  test "it runs for a revoked key" do
    key = @user.create_api_key!(name: "Revoked")
    token = key.token
    key.revoke!

    authenticate(token)

    assert_equal [[key.id, :revoked_key]], @calls.map { |call| [call[:api_key].id, call[:error_code]] }
  end

  test "it never runs for a token that names no key" do
    key = @user.create_api_key!(name: "Target", allowed_origins: "example.com")
    forged = key.token.dup
    forged[-6] = forged[-6] == "A" ? "B" : "A"

    [forged, "ak_never_minted", nil].each do |token|
      controller = authenticate(token, origin: "https://elsewhere.example")
      assert_equal :unauthorized, controller.rendered[:status]
    end

    assert_empty @calls
  end

  test "it never runs for an accepted request" do
    key = @user.create_api_key!(name: "Working", allowed_origins: "example.com")

    controller = authenticate(key.token, origin: "https://example.com")

    assert_nil controller.rendered
    assert_equal key.id, controller.current_api_key.id
    assert_empty @calls
  end

  test "a raising hook is logged and leaves the refusal and its stats exactly as they were" do
    key = @user.create_api_key!(name: "Widget", allowed_origins: "example.com")
    expected = authenticate(key.token, origin: "https://elsewhere.example").rendered
    clear_enqueued_jobs

    ApiKeys.configuration.on_key_refused = ->(**) { raise "mailer down" }
    logged = []
    FakeController.any_instance.stubs(:log_error).with { |message| logged << message }

    controller = authenticate(key.token, origin: "https://elsewhere.example")

    assert_equal expected, controller.rendered
    assert_equal 1, refusal_jobs.length, "the refusal is still recorded"
    assert_equal 1, logged.length
    assert_match "on_key_refused failed for key #{key.id} (RuntimeError)", logged.first
    refute_match "mailer down", logged.first, "the message may carry request data; only the class is logged"
  end

  test "it runs with async operations off, since it enqueues nothing itself" do
    ApiKeys.configuration.enable_async_operations = false
    key = @user.create_api_key!(name: "Widget", allowed_origins: "example.com")

    authenticate(key.token, origin: "https://elsewhere.example")

    assert_equal 1, @calls.length
  end

  test "a controller that overrides record_key_refusal keeps working, and the hook still runs once" do
    key = @user.create_api_key!(name: "Widget", allowed_origins: "example.com")

    controller = OverridingController.new(FakeRequest.new(token: key.token, origin: "https://elsewhere.example"))
    controller.send(:authenticate_api_key!)

    assert_equal [[key.id, :origin_not_allowed]], controller.overridden_calls
    assert_equal 1, refusal_jobs.length, "super still records the refusal"
    assert_equal 1, @calls.length
  end

  test "without a hook, a refusal is unchanged" do
    ApiKeys.configuration.on_key_refused = nil
    key = @user.create_api_key!(name: "Widget", allowed_origins: "example.com")

    controller = authenticate(key.token, origin: "https://elsewhere.example")

    assert_equal :origin_not_allowed, controller.rendered[:json][:error]
    assert_equal 1, refusal_jobs.length
  end

  test "a one-argument lambda receives the same three values as a hash" do
    received = nil
    ApiKeys.configuration.on_key_refused = ->(refusal) { received = refusal }
    key = @user.create_api_key!(name: "Widget", allowed_origins: "example.com")

    authenticate(key.token, origin: "https://elsewhere.example")

    assert_equal %i[api_key error_code request], received.keys
  end

  test "the setting takes a callable or nil" do
    assert_raises(ArgumentError) { ApiKeys.configuration.on_key_refused = "notify" }
    ApiKeys.configuration.on_key_refused = nil
    assert_nil ApiKeys.configuration.on_key_refused
    assert_nil ApiKeys::Configuration.new.on_key_refused
  end

  private

  def authenticate(token, scope: nil, **request_options)
    controller = FakeController.new(FakeRequest.new(token: token, **request_options))
    controller.send(:authenticate_api_key!, scope: scope)
    controller
  end

  def refusal_jobs
    enqueued_jobs.select do |job|
      job[:job] == ApiKeys::Jobs::UpdateStatsJob && ActiveJob::Arguments.deserialize(job[:args]).last.is_a?(Hash)
    end
  end
end
