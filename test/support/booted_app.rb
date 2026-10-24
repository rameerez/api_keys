# frozen_string_literal: true

# Boots a small Rails application with the api_keys engine and runs
# integration tests against it in this process: what a host app sees in its
# request log and from its own rate limits. test/booted_app_test.rb runs this
# file in a process of its own, so this application stays apart from the
# rest of the suite.
ENV["RAILS_ENV"] = "test"
ENV["DATABASE_URL"] = "sqlite3::memory:"

require "erb"
require "logger"
require "stringio"
require "rails"
require "active_record/railtie"
require "action_controller/railtie"
require "api_keys"
require "minitest/autorun"
require "action_dispatch/testing/integration"

LOG = StringIO.new

class BootedApp < Rails::Application
  config.root = __dir__
  config.eager_load = false
  config.logger = Logger.new(LOG)
  config.log_level = :info
  config.cache_store = :memory_store
  config.secret_key_base = "0" * 64
  config.hosts.clear
  config.action_controller.allow_forgery_protection = false
  # What a host's config/initializers/filter_parameter_logging.rb does.
  config.filter_parameters += %i[passw]
end
Rails.application.initialize!

ActiveRecord::Migration.verbose = false
ActiveRecord::Schema.define { create_table(:users) { |t| t.string :name } }
templates = File.expand_path("../../lib/generators/api_keys/templates", __dir__)
def migration_version = "[#{ActiveRecord::VERSION::STRING.to_f}]"
%w[create_api_keys_table create_api_keys_device_authorizations].each do |name|
  eval(ERB.new(File.read("#{templates}/#{name}.rb.erb")).result(binding), binding, "#{name}.rb") # rubocop:disable Security/Eval
end
CreateApiKeysTable.migrate(:up)
CreateApiKeysDeviceAuthorizations.migrate(:up)
ApiKeys.configure do |config|
  config.default_scopes = %w[read write]
  config.enable_async_operations = false
end

class User < ActiveRecord::Base
  has_api_keys
end

class DeviceAuthorizationsController < ActionController::API
  include ApiKeys::DeviceFlow

  private

  def device_verification_uri(user_code = nil)
    user_code ? "http://www.example.com/device?user_code=#{user_code}" : "http://www.example.com/device"
  end
end

# The person's page, as the README shows it. A header stands in for the
# app's sign-in.
class DeviceApprovalsController < ActionController::Base
  before_action { @user = User.find(request.headers["X-User"]) }
  rate_limit to: 10, within: 10.minutes, by: -> { @user.id }, only: %i[show update]

  def show
    render plain: ApiKeys::DeviceAuthorization.find_undecided_by_user_code(params[:user_code]) ? "found" : "unknown"
  end

  def update
    authorization = ApiKeys::DeviceAuthorization.find_undecided_by_user_code(params[:user_code])
    return render(plain: "unknown", status: :not_found) unless authorization

    authorization.approve!(@user, by: @user)
    render plain: "approved"
  end
end

Rails.application.routes.draw do
  post "/api/device", to: "device_authorizations#create"
  post "/api/token", to: "device_authorizations#token"
  get "/device", to: "device_approvals#show"
  post "/device", to: "device_approvals#update"
end

class BootedAppTest < ActionDispatch::IntegrationTest
  GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code"

  def app = Rails.application

  setup do
    Rails.cache.clear
    LOG.truncate(0)
    LOG.rewind
    @person = User.create!(name: "Ada")
  end

  test "the request log never shows a device code, a user code or a token" do
    post "/api/device", params: { client_id: "Fictional agent", scope: "read" }
    codes = response.parsed_body
    post "/device", params: { user_code: codes["user_code"] }, headers: { "X-User" => @person.id.to_s }
    assert_response :success
    post "/api/token", params: { grant_type: GRANT_TYPE, device_code: codes["device_code"], client_id: "Fictional agent" }
    token = response.parsed_body["access_token"]
    assert token
    get "/device", params: { user_code: codes["user_code"] }, headers: { "X-User" => @person.id.to_s }

    log = LOG.string
    assert_match "Parameters:", log, "the log has the request parameters"
    assert_match "[FILTERED]", log
    refute_includes log, codes["device_code"]
    refute_includes log, codes["user_code"]
    refute_includes log, token
    assert_includes Rails.application.config.filter_parameters, :passw, "the app's own filters stay"
  end

  test "the approval page's limit counts look-ups and approvals together, per person" do
    headers = { "X-User" => @person.id.to_s }
    5.times { get "/device", params: { user_code: "BCDF-GHJK" }, headers: headers }
    5.times { post "/device", params: { user_code: "BCDF-GHJK" }, headers: headers }
    assert_response :not_found

    post "/device", params: { user_code: "BCDF-GHJK" }, headers: headers
    assert_response :too_many_requests, "a direct guess spends the same budget as a look-up"
    get "/device", params: { user_code: "BCDF-GHJK" }, headers: headers
    assert_response :too_many_requests

    other = User.create!(name: "Grace")
    post "/device", params: { user_code: "BCDF-GHJK" }, headers: { "X-User" => other.id.to_s }
    assert_response :not_found, "another person has a budget of their own"
  end

  test "ten direct guesses use the whole budget, so a look-up is refused" do
    headers = { "X-User" => @person.id.to_s }
    10.times { post "/device", params: { user_code: "BCDF-GHJK" }, headers: headers }

    get "/device", params: { user_code: "BCDF-GHJK" }, headers: headers
    assert_response :too_many_requests
  end
end
