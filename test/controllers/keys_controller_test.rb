# frozen_string_literal: true

require "test_helper"
require "action_controller/railtie"
require "action_controller/test_case"

unless defined?(::ApplicationController)
  class ::ApplicationController < ActionController::Base
    helper_method :current_user

    def current_user
      User.find_by(id: session[:test_user_id])
    end

    def authenticate_user!
      head :unauthorized unless current_user
    end

    def default_url_options
      {}
    end
  end
end

require_relative "../../app/controllers/api_keys/application_controller"
require_relative "../../app/controllers/api_keys/keys_controller"
require_relative "../../config/routes"
ApiKeys::ApplicationController.helper(ApiKeys::Engine.routes.url_helpers)
ApiKeys::ApplicationController.helper_method(:default_url_options)

module ApiKeys
  class KeysControllerTest < ActionController::TestCase
    tests ApiKeys::KeysController

    def setup
      super
      ApiKeys.reset_configuration!
      token_session_key = "t" * ActiveSupport::MessageEncryptor.key_len("aes-256-gcm")
      @token_session_encryptor = ActiveSupport::MessageEncryptor.new(
        token_session_key,
        cipher: "aes-256-gcm",
        serializer: JSON
      )
      ApiKeys::TokenSession.stubs(:token_encryptor).returns(@token_session_encryptor)
      ApiKeys::ApiKey.delete_all
      User.delete_all
      @user = User.create!(name: "Dashboard Owner")
      @request.session[:test_user_id] = @user.id
      @routes = ApiKeys::Engine.routes
      @controller.class.allow_forgery_protection = false
      @controller.prepend_view_path File.expand_path("../../app/views", __dir__)
      @controller.singleton_class.include(ApiKeys::Engine.routes.url_helpers)
    end

    test "dashboard responses prohibit caching, MIME sniffing, and referrers" do
      get :index

      assert_response :success
      assert_includes response.headers["Cache-Control"], "no-store"
      assert_includes response.headers["Cache-Control"], "private"
      assert_equal "no-cache", response.headers["Pragma"]
      assert_equal "no-referrer", response.headers["Referrer-Policy"]
      assert_equal "nosniff", response.headers["X-Content-Type-Options"]
      assert_equal "DENY", response.headers["X-Frame-Options"]
      assert_equal "camera=(), microphone=(), geolocation=()", response.headers["Permissions-Policy"]
      csp = response.headers["Content-Security-Policy"] || @request.content_security_policy.build(
        @controller,
        @request.content_security_policy_nonce,
        @request.content_security_policy_nonce_directives
      )
      assert_includes csp, "default-src 'none'"
      assert_includes csp, "frame-ancestors 'none'"
      assert_includes csp, "form-action 'self'"
      assert_match(/script-src[^;]*'nonce-[^']+'/i, csp)
    end

    test "configured authentication method cannot succeed without an owner" do
      @request.session.delete(:test_user_id)
      ApiKeys.configuration.authenticate_owner_method = :authentication_noop
      @controller.define_singleton_method(:authentication_noop) { true }

      get :index

      assert_response :unauthorized
    end

    test "missing configured authentication method fails closed" do
      ApiKeys.configuration.authenticate_owner_method = :method_that_does_not_exist

      get :index

      assert_response :unauthorized
    end

    test "show only releases a one-time token bound to that key" do
      first = @user.create_api_key!(name: "First")
      second = @user.create_api_key!(name: "Second")
      ApiKeys::TokenSession.store(@request.session, first)

      get :show, params: { id: second.id }

      assert_redirected_to keys_path
      assert_nil @controller.instance_variable_get(:@plaintext_token)
      assert_nil @request.session[ApiKeys::TokenSession::DEFAULT_SESSION_KEY]
    end

    test "successful create stores a key-bound token payload" do
      post :create, params: { api_key: { name: "New Dashboard Key", scopes: %w[read] } }

      key = @user.api_keys.order(:created_at).last
      assert_redirected_to key_path(key)
      payload = @request.session[ApiKeys::TokenSession::DEFAULT_SESSION_KEY]
      assert_equal key.id.to_s, payload["api_key_id"]
      decrypted_payload = @token_session_encryptor.decrypt_and_verify(
        payload["ciphertext"],
        purpose: ApiKeys::TokenSession::ENCRYPTION_PURPOSE
      )
      refute_includes payload.inspect, decrypted_payload["token"]
      assert ApiKeys::Services::Digestor.match?(
        token: decrypted_payload["token"],
        stored_digest: key.token_digest,
        strategy: key.digest_algorithm.to_sym
      )

      get :show, params: { id: key.id }
      assert_response :success
      refute_match(/\son[a-z]+=/i, response.body)
      refute_match(/\sstyle=/i, response.body)
      assert_equal 1, response.body.scan(/<script\b/i).length
      assert_match(/<script\s+nonce="[^"]+">/i, response.body)
    end

    test "malformed create payloads return bad request without entering error rendering" do
      post :create, params: { api_key: "not-an-object" }

      assert_response :bad_request
    end

    test "malformed update payloads return bad request" do
      key = @user.create_api_key!(name: "Existing")

      patch :update, params: { id: key.id, api_key: "not-an-object" }

      assert_response :bad_request
      assert_equal "Existing", key.reload.name
    end

    test "unexpected creation failures never expose exception messages" do
      @user.stubs(:create_api_key!).raises(RuntimeError, "database secret: leaked-value")
      @controller.stubs(:current_api_keys_owner).returns(@user)

      post :create, params: { api_key: { name: "Failure" } }

      assert_response :unprocessable_entity
      refute_includes flash[:alert], "database secret"
      refute_includes response.body, "leaked-value"
    end

    test "keys belonging to another owner cannot be viewed" do
      other = User.create!(name: "Other Owner")
      other_key = other.create_api_key!(name: "Other Key")

      get :show, params: { id: other_key.id }

      assert_redirected_to keys_path
      assert_equal "API key not found.", flash[:alert]
    end
  end
end
