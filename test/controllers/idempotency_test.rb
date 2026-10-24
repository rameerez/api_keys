# frozen_string_literal: true

require "test_helper"
require "action_controller"
require "rack/test"

ActiveRecord::Schema.define do
  # A fictional resource of a host app.
  create_table :widgets, force: :cascade do |t|
    t.string :name, null: false
    t.references :owner, polymorphic: true
    t.timestamps
  end
end

# Writes that run once per Idempotency-Key (0.7.0), as a host app's API
# controller serves them through Rails' real request stack. Each test names
# the rule of the invoicing app that it keeps (Sol #2, #3, #4).
class IdempotencyTest < ApiKeys::Test
  include Rack::Test::Methods

  class Widget < ActiveRecord::Base
    self.table_name = "widgets"
    belongs_to :owner, polymorphic: true, optional: true
  end

  class WidgetsController < ActionController::API
    include ApiKeys::Controller
    include ApiKeys::Idempotency

    before_action :authenticate_api_key!
    around_action :run_once_per_idempotency_key

    rescue_from(ActiveRecord::RecordNotFound) { render json: { error: "not_found" }, status: :not_found }

    cattr_accessor :fail_after_write

    def index
      render json: Widget.pluck(:name)
    end

    # The secret is in this answer only, as a webhook secret is shown once.
    def create
      return render(json: { error: "name_missing" }, status: :bad_request) if params[:name].blank?

      widget = Widget.create!(name: params[:name], owner: current_api_owner)
      raise ActiveRecord::RecordNotFound if fail_after_write # a failure after the write

      render_resource widget, status: :created, secret: "shown-once-#{widget.id}"
    end

    def update
      widget = Widget.find(params[:id])
      widget.update!(name: params[:name])
      render_resource widget
    end

    # A write that answers without naming its record.
    def touch
      Widget.create!(name: "untracked")
      render json: {}, status: :ok
    end

    private

    def resource_json(widget, secret: nil)
      { id: widget.id, name: widget.name, secret: secret }.compact
    end
  end

  # A host that renders the gem's refusals in its own error shape.
  class ShapedWidgetsController < WidgetsController
    private

    def render_unauthorized(error_code:, message:, status: :unauthorized, required_scope: nil)
      render json: { code: error_code.to_s, message: message }, status: status
    end
  end

  class UnrenderedController < ActionController::API
    include ApiKeys::Controller
    include ApiKeys::Idempotency

    before_action :authenticate_api_key!
    around_action :run_once_per_idempotency_key

    def create
      render_resource Widget.create!(name: "unrendered")
    end
  end

  # A host that runs the key's around_action before authentication.
  class MisorderedController < ActionController::API
    include ApiKeys::Controller
    include ApiKeys::Idempotency

    around_action :run_once_per_idempotency_key
    before_action :authenticate_api_key!

    def create
      head :ok
    end
  end

  ROUTES = ActionDispatch::Routing::RouteSet.new.tap do |routes|
    routes.draw do
      get "/widgets", to: WidgetsController.action(:index)
      match "/widgets", to: WidgetsController.action(:index), via: :head
      post "/widgets", to: WidgetsController.action(:create)
      patch "/widgets/:id", to: WidgetsController.action(:update)
      post "/widgets/touch", to: WidgetsController.action(:touch)
      post "/shaped/widgets", to: ShapedWidgetsController.action(:create)
      post "/unrendered", to: UnrenderedController.action(:create)
      post "/misordered", to: MisorderedController.action(:create)
    end
  end

  def app
    ROUTES
  end

  def setup
    super
    ApiKeys.configure { |config| config.enable_async_operations = false }
    WidgetsController.fail_after_write = false
    Widget.delete_all
    @owner = User.create!(name: "Acme")
    @key = @owner.create_api_key!(name: "CI")
  end

  def teardown
    Widget.delete_all
    super
  end

  def api(method, path, params = {}, key: SecureRandom.uuid, token: @key.token, json: true)
    headers = { "HTTP_AUTHORIZATION" => "Bearer #{token}" }
    headers["HTTP_IDEMPOTENCY_KEY"] = key if key
    if json && !params.empty?
      headers["CONTENT_TYPE"] = "application/json"
      params = params.to_json
    end
    send(method, path, params, headers)
    last_response.body.empty? ? nil : JSON.parse(last_response.body)
  end

  test "a write needs an Idempotency-Key of 1 to 255 characters" do
    assert_equal "idempotency_key_required", api(:post, "/widgets", { name: "Gear" }, key: nil)["error"]
    assert_equal 400, last_response.status
    assert_match "Idempotency-Key", JSON.parse(last_response.body)["message"]

    api(:post, "/widgets", { name: "Gear" }, key: "")
    assert_equal 400, last_response.status
    api(:post, "/widgets", { name: "Gear" }, key: "k" * 256)
    assert_equal 400, last_response.status
    assert_empty Widget.all
    assert_empty ApiKeys::IdempotencyKey.all

    api(:post, "/widgets", { name: "Gear" }, key: "k" * 255)
    assert_equal 201, last_response.status
  end

  test "reads need no Idempotency-Key" do
    api(:get, "/widgets", key: nil)
    assert_equal 200, last_response.status
    head "/widgets", {}, { "HTTP_AUTHORIZATION" => "Bearer #{@key.token}" }
    assert_equal 200, last_response.status
    assert_empty ApiKeys::IdempotencyKey.all
  end

  test "a refused key never reaches the Idempotency-Key" do
    api(:post, "/widgets", { name: "Gear" }, token: "ak_unknown")

    assert_equal 401, last_response.status
    assert_empty ApiKeys::IdempotencyKey.all
  end

  test "a retried write runs once, and the same key with another request is refused" do
    first = api(:post, "/widgets", { name: "Gear" }, key: "widget-1")
    assert_equal 201, last_response.status
    assert_nil last_response.headers["Idempotent-Replayed"]

    again = api(:post, "/widgets", { name: "Gear" }, key: "widget-1")
    assert_equal 201, last_response.status
    assert_equal "true", last_response.headers["Idempotent-Replayed"]
    assert_equal first.except("secret"), again
    assert_equal 1, Widget.count

    assert_equal "idempotency_key_reused", api(:post, "/widgets", { name: "Sprocket" }, key: "widget-1")["error"]
    assert_equal 422, last_response.status

    other = @owner.create_api_key!(name: "Other")
    api(:post, "/widgets", { name: "Sprocket" }, key: "widget-1", token: other.token)
    assert_equal 201, last_response.status, "each API key has its own keys"
    assert_equal 2, Widget.count
  end

  test "a refused write commits nothing and leaves its key free" do
    api(:post, "/widgets", { name: "" }, key: "widget-2")
    assert_equal 400, last_response.status
    refute ApiKeys::IdempotencyKey.sole.answered?
    assert_nil ApiKeys::IdempotencyKey.sole.request_digest, "the refused request's digest is rolled back"

    api(:post, "/widgets", { name: "Gear" }, key: "widget-2")
    assert_equal 201, last_response.status, "the corrected request runs under the same key"
    assert_equal 1, Widget.count
  end

  test "a key is free again after a day, and prune! deletes the old keys" do
    api(:post, "/widgets", { name: "Gear" }, key: "widget-3")
    api(:post, "/widgets", { name: "" }, key: "widget-4")

    travel ApiKeys::IdempotencyKey::RETENTION + 1.minute do
      api(:post, "/widgets", { name: "Gear" }, key: "widget-3")
      assert_equal 201, last_response.status
      assert_nil last_response.headers["Idempotent-Replayed"]
      assert_equal 2, Widget.count
      assert_equal 1, ApiKeys::IdempotencyKey.prune!, "the day-old key of the refused write"
    end
    assert_equal ["widget-3"], ApiKeys::IdempotencyKey.pluck(:key)
  end

  test "Sol #2: a failure after the write commits nothing, and the retry writes once" do
    WidgetsController.fail_after_write = true
    api(:post, "/widgets", { name: "Gear" }, key: "widget-5")
    assert_equal 404, last_response.status
    assert_empty Widget.all
    refute ApiKeys::IdempotencyKey.sole.answered?

    WidgetsController.fail_after_write = false
    api(:post, "/widgets", { name: "Gear" }, key: "widget-5")
    assert_equal 201, last_response.status
    api(:post, "/widgets", { name: "Gear" }, key: "widget-5")
    assert_equal "true", last_response.headers["Idempotent-Replayed"]
    assert_equal 1, Widget.count
  end

  test "Sol #2: a key left without an answer by a crash runs on the retry, once" do
    ApiKeys::IdempotencyKey.create!(api_key: @key, key: "widget-6")

    2.times { api(:post, "/widgets", { name: "Gear" }, key: "widget-6") }

    assert_equal 1, Widget.count
    assert_equal "true", last_response.headers["Idempotent-Replayed"]
  end

  test "a write still running answers 409 to its retry" do
    ApiKeys::IdempotencyKey.stubs(:locked).raises(ApiKeys::IdempotencyKey::Busy)

    assert_equal "idempotency_key_in_use", api(:post, "/widgets", { name: "Gear" }, key: "widget-7")["error"]
    assert_equal 409, last_response.status
    assert_empty Widget.all
  end

  test "Sol #3: the key stands for the query and the body; a changed query is another request" do
    api(:post, "/widgets?name=Gear", {}, key: "widget-8")
    assert_equal 201, last_response.status
    assert_equal "idempotency_key_reused", api(:post, "/widgets?name=Sprocket", {}, key: "widget-8")["error"]

    api(:post, "/widgets", { name: "Cog", extra: { b: 1, a: 2 } }, key: "widget-9")
    api(:post, "/widgets", { extra: { a: 2, b: 1 }, name: "Cog" }, key: "widget-9")
    assert_equal "true", last_response.headers["Idempotent-Replayed"], "the order of the names does not matter"
    assert_equal 2, Widget.count

    api(:post, "/widgets", { name: "Cog" }, key: "widget-9")
    assert_equal 422, last_response.status, "a parameter left out is another request"
    widget = Widget.first
    api(:patch, "/widgets/#{widget.id}", { name: "Gear" }, key: "widget-8")
    assert_equal 422, last_response.status, "another method or path is another request"
  end

  test "Sol #4: a retry answers the record as it is now, without the secret of the first answer" do
    first = api(:post, "/widgets", { name: "Gear" }, key: "widget-10")
    widget = Widget.find(first["id"])
    assert_equal "shown-once-#{widget.id}", first["secret"]

    api(:patch, "/widgets/#{widget.id}", { name: "Sprocket" }, key: "widget-11")
    again = api(:post, "/widgets", { name: "Gear" }, key: "widget-10")

    assert_equal "true", last_response.headers["Idempotent-Replayed"]
    assert_equal({ "id" => widget.id, "name" => "Sprocket" }, again)
    record = ApiKeys::IdempotencyKey.find_by!(key: "widget-10")
    assert_equal widget, record.resource
    assert_equal 201, record.response_status
    refute_includes record.attributes.to_json, "shown-once", "a key keeps no body"
  end

  test "a retry for a record that no longer exists is not found" do
    first = api(:post, "/widgets", { name: "Gear" }, key: "widget-12")
    Widget.where(id: first["id"]).delete_all

    assert_equal({ "error" => "not_found" }, api(:post, "/widgets", { name: "Gear" }, key: "widget-12"))
    assert_equal 404, last_response.status
  end

  test "a write that answers without its record fails and commits nothing" do
    error = assert_raises(ArgumentError) { api(:post, "/widgets/touch") }

    assert_match "answers with the record", error.message
    assert_empty Widget.all
    refute ApiKeys::IdempotencyKey.sole.answered?
  end

  test "refusals render through render_unauthorized, so a host's own error shape applies" do
    api(:post, "/shaped/widgets", { name: "Gear" }, key: nil)

    assert_equal 400, last_response.status
    assert_equal "idempotency_key_required", JSON.parse(last_response.body)["code"]
  end

  test "refusal messages can be changed with I18n" do
    I18n.backend.store_translations(:en, api_keys: { errors: { idempotency_key_reused: "New request, new key." } })
    api(:post, "/widgets", { name: "Gear" }, key: "widget-13")

    assert_equal "New request, new key.", api(:post, "/widgets", { name: "Cog" }, key: "widget-13")["message"]
  ensure
    I18n.reload!
  end

  test "a host must define resource_json" do
    error = assert_raises(NotImplementedError) { api(:post, "/unrendered") }

    assert_match "resource_json", error.message
    assert_empty Widget.all
  end

  test "the key's around_action needs authenticate_api_key! first" do
    assert_raises(ApiKeys::Error) { api(:post, "/misordered") }
  end
end
