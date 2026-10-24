# frozen_string_literal: true

require "test_helper"
require "action_controller"
require "rack/test"

# Scope by HTTP method (0.7.0): one line asks reads for one scope and
# writes for another, as an invoicing app on the fleet does for its API.
class ScopeByMethodTest < ApiKeys::Test
  include Rack::Test::Methods

  class FakeRequest
    attr_reader :headers, :query_parameters, :protocol, :uuid, :remote_ip, :request_method

    def initialize(token, request_method)
      @headers = { "Authorization" => "Bearer #{token}" }
      @query_parameters = {}
      @protocol = "https://"
      @remote_ip = "203.0.113.7"
      @uuid = SecureRandom.uuid
      @request_method = request_method
    end
  end

  class FakeController
    include ApiKeys::Authentication

    attr_reader :rendered, :request

    def initialize(request)
      @request = request
    end

    def render(json:, status:)
      @rendered = { json: json, status: status }
    end
  end

  # The host's one line, and an action that names another scope.
  class ProjectsController < ActionController::API
    include ApiKeys::Controller

    before_action -> { authenticate_api_key!(scope: required_scope) }

    def index = render(json: { ok: true })
    def create = render(json: { ok: true }, status: :created)
    def export = render(json: { ok: true })

    private

    def required_scope
      action_name == "export" ? "export" : { read: "read", write: "write" }
    end
  end

  ROUTES = ActionDispatch::Routing::RouteSet.new.tap do |routes|
    routes.draw do
      get "/projects", to: ProjectsController.action(:index)
      post "/projects", to: ProjectsController.action(:create)
      get "/projects/export", to: ProjectsController.action(:export)
    end
  end

  def app
    ROUTES
  end

  def setup
    super
    ApiKeys.configure { |config| config.enable_async_operations = false }
    @owner = User.create!(name: "Acme")
  end

  def key_with(*scopes)
    @owner.create_api_key!(name: "Key", scopes: scopes)
  end

  def authenticate(key, request_method, scope:)
    controller = FakeController.new(FakeRequest.new(key.token, request_method))
    controller.send(:authenticate_api_key!, scope: scope)
    controller
  end

  BY_METHOD = { read: "read", write: "write" }.freeze

  test "GET and HEAD need the read scope; every other method needs the write scope" do
    reader = key_with("read")
    writer = key_with("write")

    %w[GET HEAD].each do |method|
      assert_nil authenticate(reader, method, scope: BY_METHOD).rendered, method
      assert_equal "read", authenticate(writer, method, scope: BY_METHOD).rendered[:json][:required_scope], method
    end
    %w[POST PUT PATCH DELETE OPTIONS].each do |method|
      assert_nil authenticate(writer, method, scope: BY_METHOD).rendered, method
      refused = authenticate(reader, method, scope: BY_METHOD).rendered
      assert_equal :forbidden, refused[:status], method
      assert_equal :missing_scope, refused[:json][:error]
      assert_equal "write", refused[:json][:required_scope]
    end
  end

  test "each side takes what scope: takes: a scope, a list of scopes, or nil for none" do
    key = key_with("write", "admin")
    scope = { read: nil, write: %w[write admin] }

    assert_nil authenticate(key_with, "GET", scope: scope).rendered, "any valid key reads"
    assert_nil authenticate(key, "POST", scope: scope).rendered
    assert_equal :missing_scope, authenticate(key_with("write"), "POST", scope: scope).rendered[:json][:error]
    assert_nil authenticate(key, "POST", scope: { "read" => "read", "write" => "write" }).rendered, "string names work"
  end

  test "both sides are required, so a forgotten one never leaves requests unchecked" do
    key = key_with("read")

    assert_raises(ArgumentError) { authenticate(key, "GET", scope: { read: "read" }) }
    assert_raises(ArgumentError) { authenticate(key, "POST", scope: { write: "write" }) }
    assert_raises(ArgumentError) { authenticate(key, "POST", scope: { read: "read", write: "write", delete: "admin" }) }
  end

  test "the after_authentication callback names the scope this request needed" do
    contexts = []
    ApiKeys.configure do |config|
      config.enable_async_operations = true
      config.after_authentication = ->(context) { contexts << context }
    end
    previous_adapter = ActiveJob::Base.queue_adapter
    ActiveJob::Base.queue_adapter = :inline

    authenticate(key_with("read"), "PATCH", scope: BY_METHOD)

    assert_equal({ required: "write", passed: false }, contexts.sole[:required_scope_check])
  ensure
    ActiveJob::Base.queue_adapter = previous_adapter if previous_adapter
  end

  test "in a controller: one line for reads and writes, and an action may name another scope" do
    reader = key_with("read")
    writer = key_with("read", "write")

    get "/projects", {}, { "HTTP_AUTHORIZATION" => "Bearer #{reader.token}" }
    assert_equal 200, last_response.status
    post "/projects", {}, { "HTTP_AUTHORIZATION" => "Bearer #{reader.token}" }
    assert_equal 403, last_response.status
    assert_equal "write", JSON.parse(last_response.body)["required_scope"]
    post "/projects", {}, { "HTTP_AUTHORIZATION" => "Bearer #{writer.token}" }
    assert_equal 201, last_response.status

    get "/projects/export", {}, { "HTTP_AUTHORIZATION" => "Bearer #{writer.token}" }
    assert_equal 403, last_response.status
    assert_equal "export", JSON.parse(last_response.body)["required_scope"]
    get "/projects/export", {}, { "HTTP_AUTHORIZATION" => "Bearer #{key_with('export').token}" }
    assert_equal 200, last_response.status
  end
end
