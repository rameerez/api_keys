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

    # =========================================================================
    # 0.5.1: clearing every scope checkbox must clear the scopes
    # =========================================================================

    test "both scope checkbox groups render one empty sentinel" do
      with_owner_default_scopes(%w[read write]) do
        get :new
        assert_select 'input[type="hidden"][name="api_key[scopes][]"][value=""]', count: 1
        assert_select 'input[type="checkbox"][name="api_key[scopes][]"]', count: 2

        key = @user.create_api_key!(name: "Existing", scopes: %w[read])
        get :edit, params: { id: key.id }
        assert_select 'input[type="hidden"][name="api_key[scopes][]"][value=""]', count: 1
        assert_select 'input[type="checkbox"][name="api_key[scopes][]"]', count: 2
      end
    end

    test "creating a key with every scope unchecked creates a key with no scopes" do
      with_owner_default_scopes(%w[read write]) do
        get :new
        submission = browser_submission(response.body) { |form| uncheck_all_scopes(form) }

        post :create, params: submission

        key = @user.api_keys.order(:created_at).last
        assert_redirected_to key_path(key)
        assert_equal [], key.reload.scopes, "a permissionless key must not receive the default scopes"
        refute key.allows_scope?("read")
        refute key.allows_scope?("write")
        # What makes it work: the browser sends the sentinel and nothing else.
        assert_equal [""], submission.dig("api_key", "scopes")
      end
    end

    test "updating a key with every scope unchecked removes its scopes" do
      with_owner_default_scopes(%w[read write]) do
        key = @user.create_api_key!(name: "Reader", scopes: %w[read])
        assert key.allows_scope?("read")

        get :edit, params: { id: key.id }
        submission = browser_submission(response.body) { |form| uncheck_all_scopes(form) }

        patch :update, params: submission.merge("id" => key.id)

        assert_redirected_to keys_path
        assert_equal [], key.reload.scopes, "clearing every box must not keep the old scopes"
        refute key.allows_scope?("read")
        assert_equal [""], submission.dig("api_key", "scopes")
      end
    end

    test "the rendered forms still submit exactly the boxes that stay checked" do
      with_owner_default_scopes(%w[read write]) do
        get :new
        submission = browser_submission(response.body) do |form|
          form.css('input[type="checkbox"][value="read"]').each { |box| box.remove_attribute("checked") }
        end
        post :create, params: submission
        assert_equal %w[write], @user.api_keys.order(:created_at).last.scopes

        key = @user.create_api_key!(name: "Writer", scopes: %w[write])
        get :edit, params: { id: key.id }
        submission = browser_submission(response.body) do |form|
          form.at_css('input[type="checkbox"][value="read"]')["checked"] = "checked"
        end
        patch :update, params: submission.merge("id" => key.id)
        assert_equal %w[write read], key.reload.scopes, "existing order kept, new grant appended"
      end
    end

    test "a request without the scopes parameter keeps the programmatic defaults" do
      with_owner_default_scopes(%w[read write]) do
        post :create, params: { api_key: { name: "No Scope Field" } }
        assert_equal %w[read write], @user.api_keys.order(:created_at).last.scopes

        key = @user.create_api_key!(name: "Reader", scopes: %w[read])
        patch :update, params: { id: key.id, api_key: { name: "Renamed" } }
        assert_equal %w[read], key.reload.scopes
      end
    end

    test "a failed creation re-renders cleared scope boxes as cleared" do
      with_owner_default_scopes(%w[read write]) do
        get :new
        submission = browser_submission(response.body) do |form|
          uncheck_all_scopes(form)
          form.at_css('input[name="api_key[allowed_origins]"]')["value"] = "*"
        end

        post :create, params: submission

        assert_response :unprocessable_entity
        assert_select 'input[type="checkbox"][name="api_key[scopes][]"]', count: 2
        assert_select 'input[type="checkbox"][name="api_key[scopes][]"][checked]', count: 0

        resubmission = browser_submission(response.body) do |form|
          form.at_css('input[name="api_key[allowed_origins]"]')["value"] = ""
        end
        post :create, params: resubmission
        assert_equal [], @user.api_keys.order(:created_at).last.scopes
      end
    end

    # The edit form offers only the owner's default scopes. With the sentinel,
    # a rename of a key holding a scope outside that list used to save it with
    # no scopes at all (0.5.0 kept it, because nothing was submitted).
    test "a rename keeps a scope the edit form never offered" do
      configure_secret_type(permissions: %w[read write admin])
      with_owner_default_scopes(%w[read write]) do
        key = @user.create_api_key!(name: "Admin Key", key_type: :secret, scopes: %w[admin])

        get :edit, params: { id: key.id }
        assert_select 'input[type="checkbox"][value="admin"]', count: 0
        submission = browser_submission(response.body) do |form|
          form.at_css('input[name="api_key[name]"]')["value"] = "Renamed Admin Key"
        end
        patch :update, params: submission.merge("id" => key.id)

        assert_redirected_to keys_path
        key.reload
        assert_equal "Renamed Admin Key", key.name
        assert_equal %w[admin], key.scopes
        assert key.allows_scope?("admin")

        # The form tells the owner which scopes it leaves alone.
        get :edit, params: { id: key.id }
        assert_select "small.api-keys-form-help", text: /This key also holds\s+admin,\s+which this form does not change/
      end
    end

    test "clearing every box removes every offered scope and keeps the others" do
      configure_secret_type(permissions: %w[read write admin])
      with_owner_default_scopes(%w[read write]) do
        key = @user.create_api_key!(name: "Wide Key", key_type: :secret, scopes: %w[read admin write])

        get :edit, params: { id: key.id }
        patch :update, params: browser_submission(response.body) { |form| uncheck_all_scopes(form) }.merge("id" => key.id)

        assert_redirected_to keys_path
        assert_equal %w[admin], key.reload.scopes
        refute key.allows_scope?("read")
        refute key.allows_scope?("write")
      end
    end

    test "an update cannot grant a scope the form never offered" do
      configure_secret_type(permissions: %w[read write admin])
      with_owner_default_scopes(%w[read write]) do
        key = @user.create_api_key!(name: "Reader", key_type: :secret, scopes: %w[read])

        patch :update, params: { id: key.id, api_key: { name: "Reader", scopes: ["", "read", "admin"] } }

        assert_redirected_to keys_path
        assert_equal %w[read], key.reload.scopes
      end
    end

    # A kept scope that a narrowed ceiling excludes used to make every save of
    # the key fail the ceiling validation (422), even a rename, and even the
    # origin tightening a non-revocable key relies on. Authentication already
    # denies such a scope, so the save drops it.
    test "a rename drops a kept scope that a narrowed ceiling excludes" do
      configure_key_types(secret: %w[read write admin])
      with_owner_default_scopes(%w[read write]) do
        key = @user.create_api_key!(name: "Admin Key", key_type: :secret, scopes: %w[read admin])
        configure_key_types(secret: %w[read write])
        refute ApiKeys::ApiKey.find(key.id).valid?, "precondition: admin now exceeds the ceiling"

        get :edit, params: { id: key.id }
        edit_html = response.body
        submission = browser_submission(edit_html) do |form|
          form.at_css('input[name="api_key[name]"]')["value"] = "Renamed"
        end
        patch :update, params: submission.merge("id" => key.id)

        assert_redirected_to keys_path
        key.reload
        assert_equal "Renamed", key.name
        assert_equal %w[read], key.scopes
        notes = Nokogiri::HTML(edit_html).css("small.api-keys-form-help").map { |note| note.text.squish }
        assert_includes notes, "admin is no longer allowed for this key and will be removed when you save."
      end
    end

    test "a non-revocable key can still tighten its origins after its ceiling narrowed" do
      configure_key_types(secret: %w[read], permanent: %w[read write admin])
      with_owner_default_scopes(%w[read write]) do
        key = @user.create_api_key!(name: "Permanent", key_type: :permanent, scopes: %w[read admin])
        configure_key_types(secret: %w[read], permanent: %w[read write])
        refute ApiKeys::ApiKey.find(key.id).revocable?

        get :edit, params: { id: key.id }
        submission = browser_submission(response.body) do |form|
          form.at_css('input[name="api_key[allowed_origins]"]')["value"] = "example.com"
        end
        patch :update, params: submission.merge("id" => key.id)

        assert_redirected_to keys_path
        key.reload
        assert_equal %w[read], key.scopes
        assert_equal ["example.com"], key.allowed_origins
      end
    end

    test "a held offered scope the ceiling now excludes is dropped even though its box was checked" do
      configure_key_types(secret: %w[read write])
      with_owner_default_scopes(%w[read write]) do
        key = @user.create_api_key!(name: "Writer", key_type: :secret, scopes: %w[read write])
        configure_key_types(secret: %w[read])

        get :edit, params: { id: key.id }
        edit_html = response.body
        patch :update, params: { id: key.id, api_key: { name: "Writer", scopes: ["", "read", "write"] } }

        assert_redirected_to keys_path
        assert_equal %w[read], key.reload.scopes
        assert_nil Nokogiri::HTML(edit_html).at_css('input[type="checkbox"][value="write"][checked]'),
                   "the form shows the box unchecked, matching what a save keeps"
      end
    end

    test "a save without scope boxes still drops scopes the ceiling excludes" do
      configure_key_types(secret: %w[read admin])
      key = @user.create_api_key!(name: "Admin Key", key_type: :secret, scopes: %w[read admin])
      configure_key_types(secret: %w[read])

      get :edit, params: { id: key.id }
      assert_select 'input[type="checkbox"][name="api_key[scopes][]"]', count: 0
      patch :update, params: browser_submission(response.body).merge("id" => key.id)

      assert_redirected_to keys_path
      assert_equal %w[read], key.reload.scopes
    end

    test "a newly checked scope outside the ceiling is still refused" do
      configure_key_types(secret: %w[read write])
      with_owner_default_scopes(%w[read write admin]) do
        key = @user.create_api_key!(name: "Reader", key_type: :secret, scopes: %w[read])

        patch :update, params: { id: key.id, api_key: { name: "Reader", scopes: ["", "read", "admin"] } }

        assert_response :unprocessable_entity
        assert_includes flash[:alert], "exceed the configured permission ceiling"
        assert_equal %w[read], key.reload.scopes
      end
    end

    # =========================================================================
    # 0.5.1: a stored malformed policy survives a rename only as a refusal
    # =========================================================================

    test "the edit form shows malformed stored entries and refuses a rename-only save" do
      {
        { "ips" => [nil] } => ["api_key[allowed_ips]", "null"],
        { "ips" => nil } => ["api_key[allowed_ips]", "null"],
        { "origins" => [""] } => ["api_key[allowed_origins]", '""'],
        { "origins" => ["example.com", false] } => ["api_key[allowed_origins]", "example.com, false"]
      }.each do |stored, (field, shown)|
        key = @user.create_api_key!(name: "Damaged")
        key.update_column(:restrictions, stored)

        get :edit, params: { id: key.id }
        edit_html = response.body
        submission = browser_submission(edit_html) do |form|
          form.at_css('input[name="api_key[name]"]')["value"] = "Renamed"
        end
        patch :update, params: submission.merge("id" => key.id)

        assert_response :unprocessable_entity, stored.inspect
        key.reload
        assert_equal "Damaged", key.name, stored.inspect
        assert_equal stored, key[:restrictions], "#{stored.inspect} must not be rewritten"
        assert key.restrictions.malformed?, stored.inspect
        # The owner sees what is stored instead of an empty, "unrestricted" field.
        assert_equal shown, Nokogiri::HTML(edit_html).at_css("input[name=\"#{field}\"]")["value"], stored.inspect
      end
    end

    test "correcting a malformed stored field saves the corrected policy" do
      key = @user.create_api_key!(name: "Damaged")
      key.update_column(:restrictions, { "ips" => [nil] })

      get :edit, params: { id: key.id }
      submission = browser_submission(response.body) do |form|
        form.at_css('input[name="api_key[allowed_ips]"]')["value"] = "10.0.0.0/8"
      end
      patch :update, params: submission.merge("id" => key.id)

      assert_redirected_to keys_path
      assert_equal({ "ips" => ["10.0.0.0/8"] }, key.reload[:restrictions])
    end

    test "a rename keeps a valid stored policy as it is" do
      key = @user.create_api_key!(name: "Locked", allowed_origins: "example.com, *.example.com", allowed_ips: "10.0.0.0/8")

      get :edit, params: { id: key.id }
      submission = browser_submission(response.body) do |form|
        form.at_css('input[name="api_key[name]"]')["value"] = "Still Locked"
      end
      patch :update, params: submission.merge("id" => key.id)

      assert_redirected_to keys_path
      key.reload
      assert_equal "Still Locked", key.name
      assert_equal ["example.com", "*.example.com"], key.allowed_origins
      assert_equal ["10.0.0.0/8"], key.allowed_ips
    end

    # =========================================================================
    # 0.5.1: CSRF, cross-owner writes, and revocation after a policy change
    # =========================================================================

    test "state-changing dashboard actions refuse requests without a CSRF token" do
      @controller.class.allow_forgery_protection = true
      key = @user.create_api_key!(name: "Protected")

      assert_raises(ActionController::InvalidAuthenticityToken) do
        post :create, params: { api_key: { name: "Forged" } }
      end
      assert_raises(ActionController::InvalidAuthenticityToken) do
        post :revoke, params: { id: key.id }
      end
      assert_raises(ActionController::InvalidAuthenticityToken) do
        patch :update, params: { id: key.id, api_key: { name: "Forged" } }
      end

      assert_equal ["Protected"], @user.api_keys.pluck(:name)
      refute key.reload.revoked?
    ensure
      @controller.class.allow_forgery_protection = false
    end

    test "the rendered form's CSRF token is accepted" do
      @controller.class.allow_forgery_protection = true

      get :new
      submission = browser_submission(response.body)
      assert submission["authenticity_token"].present?

      post :create, params: submission

      assert_redirected_to key_path(@user.api_keys.order(:created_at).last)
    ensure
      @controller.class.allow_forgery_protection = false
    end

    test "keys belonging to another owner cannot be updated" do
      other = User.create!(name: "Other Owner")
      other_key = other.create_api_key!(name: "Other Key", scopes: %w[read])

      patch :update, params: { id: other_key.id, api_key: { name: "Hijacked", scopes: [""], allowed_ips: "192.0.2.1" } }

      assert_redirected_to keys_path
      assert_equal "API key not found.", flash[:alert]
      other_key.reload
      assert_equal "Other Key", other_key.name
      assert_equal %w[read], other_key.scopes
      refute other_key.restricted?
    end

    test "keys belonging to another owner cannot be revoked" do
      other = User.create!(name: "Other Owner")
      other_key = other.create_api_key!(name: "Other Key")

      post :revoke, params: { id: other_key.id }

      assert_redirected_to keys_path
      assert_equal "API key not found.", flash[:alert]
      refute other_key.reload.revoked?
    end

    test "the dashboard revokes a key whose type ceiling was narrowed after issue" do
      configure_secret_type(permissions: %w[read write])
      key = @user.create_api_key!(name: "Wide", key_type: :secret, scopes: %w[read write])
      configure_secret_type(permissions: %w[read])
      refute key.reload.valid?, "precondition: the stored scopes now exceed the ceiling"

      post :revoke, params: { id: key.id }

      assert_redirected_to keys_path
      assert_equal "API key revoked successfully.", flash[:notice]
      assert key.reload.revoked?
    end

    # =========================================================================
    # 0.5.1: the one-time token page cannot be replayed with a copied session
    # =========================================================================

    test "a copied pre-consumption session cannot show the token a second time" do
      Rails.stubs(:cache).returns(ActiveSupport::Cache::MemoryStore.new)
      post :create, params: { api_key: { name: "Replay Target" } }
      key = @user.api_keys.order(:created_at).last
      copied_payload = @request.session[ApiKeys::TokenSession::DEFAULT_SESSION_KEY].deep_dup

      get :show, params: { id: key.id }
      assert_response :success
      assert @controller.instance_variable_get(:@plaintext_token).present?

      # Replay the cookie as it was before the token page consumed it.
      @request.session[ApiKeys::TokenSession::DEFAULT_SESSION_KEY] = copied_payload
      get :show, params: { id: key.id }

      assert_redirected_to keys_path
      assert_nil @controller.instance_variable_get(:@plaintext_token)
    end

    private

    def with_owner_default_scopes(scopes)
      settings = User.api_keys_settings.merge(default_scopes: scopes.map(&:freeze).freeze).freeze
      User.stubs(:api_keys_settings).returns(settings)
      yield
    end

    def configure_secret_type(permissions:)
      ApiKeys.configure do |config|
        config.key_types = { secret: { prefix: "sk", permissions: permissions } }
        config.environments = { test: { prefix_segment: "test" } }
        config.current_environment = :test
      end
    end

    def configure_key_types(secret:, permanent: nil)
      types = { secret: { prefix: "sk", permissions: secret } }
      types[:permanent] = { prefix: "pk", permissions: permanent, revocable: false } if permanent
      ApiKeys.configure do |config|
        config.key_types = types
        config.environments = { test: { prefix_segment: "test" } }
        config.current_environment = :test
      end
    end

    def uncheck_all_scopes(form)
      form.css('input[type="checkbox"][name="api_key[scopes][]"]').each { |box| box.remove_attribute("checked") }
    end

    # Serializes the dashboard form the way a browser does (successful
    # controls only: enabled fields, checked boxes, each select's selected
    # option) and parses the body the way Rack does. The block may edit the
    # parsed form first, as a person would before pressing submit.
    def browser_submission(html)
      document = Nokogiri::HTML(html)
      form = document.at_css("form#api-keys-key-form")
      raise "key form not rendered" unless form

      yield form if block_given?

      pairs = form.css("input, select, textarea").filter_map do |field|
        name = field["name"]
        next if name.nil? || field.has_attribute?("disabled")

        case field.name
        when "select"
          option = field.at_css("option[selected]") || field.at_css("option")
          [name, option ? (option["value"] || option.text) : ""]
        when "textarea"
          [name, field.text]
        else
          type = (field["type"] || "text").downcase
          next if %w[submit button image reset file].include?(type)
          next if %w[checkbox radio].include?(type) && !field.has_attribute?("checked")

          [name, field["value"] || (type == "checkbox" ? "on" : "")]
        end
      end

      parsed = Rack::Utils.parse_nested_query(URI.encode_www_form(pairs))
      parsed.delete("_method")
      parsed
    end

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
