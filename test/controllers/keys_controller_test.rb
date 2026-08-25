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
      csp = emitted_content_security_policy
      assert_includes csp, "frame-ancestors 'none'"
      assert_includes csp, "form-action 'self'"
      assert_match(/script-src[^;]*'nonce-[^']+'/i, csp)
    end

    test "default dashboard policy keeps host layout assets loadable" do
      get :index

      assert_response :success
      csp = emitted_content_security_policy

      # A host layout's own stylesheet_link_tag / javascript_include_tag never
      # carry the nonce unless the host enables content_security_policy_nonce_auto,
      # so the default policy has to trust same-origin assets or the dashboard
      # renders unstyled and inert in a browser.
      assert_includes csp, "default-src 'self'"
      assert_match(/(\A|;\s*)script-src 'self' 'nonce-[^']+'/, csp)
      assert_match(/(\A|;\s*)style-src 'self' 'nonce-[^']+'/, csp)
      assert_includes csp, "font-src 'self' data:"
      assert_includes csp, "img-src 'self' https: data:"

      # Structural hardening survives the relaxation.
      assert_includes csp, "base-uri 'none'"
      assert_includes csp, "object-src 'none'"
      assert_includes csp, "frame-ancestors 'none'"
      assert_includes csp, "frame-src 'none'"
      assert_includes csp, "form-action 'self'"
      assert_includes csp, "connect-src 'self'"
      refute_includes csp, "'unsafe-inline'"
      refute_includes csp, "'unsafe-eval'"
    end

    test "strict dashboard policy still emits the nonce-only policy" do
      ApiKeys.configuration.dashboard_content_security_policy = :strict

      get :index

      assert_response :success
      csp = emitted_content_security_policy

      # `'none'` next to a nonce is ignored by the CSP grammar, so the nonce is
      # the only effective source: no same-origin script or stylesheet loads.
      assert_includes csp, "default-src 'none'"
      assert_match(/(\A|;\s*)script-src 'none' 'nonce-[^']+'/, csp)
      assert_match(/(\A|;\s*)style-src 'none' 'nonce-[^']+'/, csp)
      refute_match(/script-src[^;]*'self'/, csp)
      refute_match(/style-src[^;]*'self'/, csp)
      assert_includes csp, "img-src 'self' data:"
      refute_includes csp, "font-src"

      assert_includes csp, "base-uri 'none'"
      assert_includes csp, "object-src 'none'"
      assert_includes csp, "frame-ancestors 'none'"
    end

    test "disabled dashboard policy leaves the host policy untouched" do
      ApiKeys.configuration.dashboard_content_security_policy = false

      get :index

      assert_response :success
      assert_nil @request.content_security_policy
      assert_nil response.headers["Content-Security-Policy"]

      # Security headers are independent of the CSP setting.
      assert_equal "DENY", response.headers["X-Frame-Options"]
      assert_includes response.headers["Cache-Control"], "no-store"
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

    test "the new key form offers the request restriction fields" do
      get :new

      assert_response :success
      assert_includes response.body, "Allowed web origins"
      assert_includes response.body, "api_key[allowed_origins]"
      assert_includes response.body, "Allowed IP addresses"
      assert_includes response.body, "api_key[allowed_ips]"
    end

    test "the new key form derives dynamic fields from key type policy" do
      ApiKeys.configure do |config|
        config.key_types = {
          browser: { prefix: "pk", permissions: %w[read], public: true, restrictions: [:origins] },
          permanent_server: { prefix: "sk", permissions: :all, revocable: false, restrictions: [:ips] }
        }
        config.environments = { test: { prefix_segment: "test" } }
        config.current_environment = :test
      end

      get :new

      assert_response :success
      assert_includes response.body, 'data-api-keys-restriction-kind="origins"'
      assert_includes response.body, 'data-api-keys-restriction-kind="ips"'
      assert_includes response.body, '"browser":{"restrictions":["origins"],"expirable":true}'
      assert_includes response.body, '"permanent_server":{"restrictions":["ips"],"expirable":false}'
      assert_match(/<script nonce="[^"]+">/, response.body)
    end

    test "failed creation preserves typed form values" do
      ApiKeys.configure do |config|
        config.key_types = {
          browser: { prefix: "pk", permissions: %w[read], public: true, restrictions: [:origins] }
        }
        config.environments = { test: { prefix_segment: "test" } }
        config.current_environment = :test
      end

      post :create, params: {
        api_key: {
          name: "Broken Browser Key",
          key_type: "browser",
          expires_at_preset: "30_days",
          allowed_origins: "https://"
        }
      }

      assert_response :unprocessable_entity
      assert_select 'option[value="browser"][selected]'
      assert_select 'option[value="30_days"][selected]'
      assert_select 'input[name="api_key[allowed_origins]"][value="https://"]'
    end

    test "the edit form shows a key's current restrictions" do
      key = @user.create_api_key!(name: "Widget", allowed_origins: "example.com, *.example.com")

      get :edit, params: { id: key.id }

      assert_response :success
      assert_includes response.body, "example.com, *.example.com"
    end

    test "create locks the new key to the submitted origins and addresses" do
      post :create, params: { api_key: { name: "Widget Key", allowed_origins: "https://Example.com/, *.example.com",
                                         allowed_ips: "10.0.0.0/8" } }

      key = @user.api_keys.order(:created_at).last
      assert_redirected_to key_path(key)
      assert_equal ["example.com", "*.example.com"], key.allowed_origins
      assert_equal ["10.0.0.0/8"], key.allowed_ips
    end

    test "update can tighten and clear a key's restrictions" do
      key = @user.create_api_key!(name: "Widget", allowed_origins: "example.com")

      patch :update, params: { id: key.id, api_key: { name: "Widget", allowed_origins: "shop.example.com" } }

      assert_redirected_to keys_path
      assert_equal ["shop.example.com"], key.reload.allowed_origins

      patch :update, params: { id: key.id, api_key: { name: "Widget", allowed_origins: "" } }

      refute key.reload.restricted?
    end

    test "update rejects a malformed restriction entry without saving it" do
      key = @user.create_api_key!(name: "Widget", allowed_origins: "example.com")

      patch :update, params: { id: key.id, api_key: { name: "Widget", allowed_origins: "*" } }

      assert_response :unprocessable_entity
      assert_includes flash[:alert], "bare hosts"
      assert_equal ["example.com"], key.reload.allowed_origins
    end

    test "the restricted badge appears only for keys that carry restrictions" do
      @user.create_api_key!(name: "Locked", allowed_origins: "example.com")

      get :index

      assert_response :success
      assert_includes response.body, "api-keys-badge api-keys-badge-restricted"

      ApiKeys::ApiKey.delete_all
      @user.create_api_key!(name: "Open")

      get :index

      refute_includes response.body, "api-keys-badge api-keys-badge-restricted"
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

    private

    # Functional tests bypass the CSP middleware, so build the header the way the
    # middleware would from whatever policy the controller declared.
    def emitted_content_security_policy
      response.headers["Content-Security-Policy"] || @request.content_security_policy.build(
        @controller,
        @request.content_security_policy_nonce,
        @request.content_security_policy_nonce_directives
      )
    end
  end
end
