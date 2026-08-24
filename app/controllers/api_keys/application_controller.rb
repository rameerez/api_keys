# frozen_string_literal: true

require "securerandom"

module ApiKeys
  # Base controller for the ApiKeys engine.
  # Inherits from the host application's configured controller
  # (defaults to ::ApplicationController).
  # Includes common engine functionality.
  class ApplicationController < ApiKeys.configuration.parent_controller_class
    # Protect from forgery if the parent controller does
    # This ensures CSRF protection behaves consistently with the host app.
    protect_from_forgery with: :exception if respond_to?(:protect_from_forgery)

    # Include the main controller concern which bundles authentication and tenant resolution
    include ApiKeys::Controller

    # The dashboard renders credential material, so give it an enforcing,
    # self-contained CSP even when the host application has not configured one.
    # Preserve any host directives we do not explicitly tighten.
    #
    # The policy is selected by `ApiKeys.configuration.dashboard_content_security_policy`
    # and resolved per request, so host applications can relax or disable it from
    # an initializer. See `apply_api_keys_content_security_policy` below.
    before_action :apply_api_keys_content_security_policy

    # Ensure the owner is authenticated for all actions within this engine
    # This uses the configured authentication method (defaults to authenticate_user!)
    before_action :authenticate_api_keys_owner!
    after_action :set_api_keys_security_headers

    private

    # Declares the dashboard's Content Security Policy for this request.
    #
    # `:default` keeps every structural protection (no framing, no plugins, no
    # `<base>` hijacking, same-origin form submission) while still trusting
    # same-origin scripts, styles, and fonts. That matters because Rails only
    # stamps the per-request nonce onto `stylesheet_link_tag` / `javascript_include_tag`
    # when the host sets `config.content_security_policy_nonce_auto`, which is off
    # by default and which this engine cannot turn on for the host. Without a
    # source expression the host layout's own asset tags are blocked and the
    # dashboard renders unstyled and inert.
    #
    # `:strict` restores the nonce-only policy for applications whose layout
    # serves nothing un-nonced on engine pages. `false`/`nil` declares nothing.
    def apply_api_keys_content_security_policy
      mode = ApiKeys.configuration.dashboard_content_security_policy
      return unless mode # false/nil: leave the host application's policy alone
      return unless request.respond_to?(:content_security_policy=)

      prepare_api_keys_content_security_policy_nonce

      policy = request.content_security_policy&.clone || ActionDispatch::ContentSecurityPolicy.new
      policy.base_uri :none
      policy.object_src :none
      policy.frame_ancestors :none
      policy.frame_src :none
      policy.form_action :self
      policy.connect_src :self

      if mode == :strict
        # Rails appends the per-request nonce to script-src/style-src. `none`
        # leaves the nonce as the only effective source instead of trusting
        # every same-origin script or stylesheet.
        policy.default_src :none
        policy.script_src :none
        policy.style_src :none
        policy.img_src :self, :data
      else
        policy.default_src :self
        policy.script_src :self
        policy.style_src :self
        policy.font_src :self, :data
        policy.img_src :self, :https, :data
      end

      request.content_security_policy = policy
      request.content_security_policy_report_only = false if request.respond_to?(:content_security_policy_report_only=)
    end

    def prepare_api_keys_content_security_policy_nonce
      return unless request.respond_to?(:content_security_policy_nonce_generator=)

      request.content_security_policy_nonce_generator ||= ->(_request) { SecureRandom.base64(16) }
      directives = Array(request.content_security_policy_nonce_directives)
      request.content_security_policy_nonce_directives = directives | %w[script-src style-src]
      request.content_security_policy_nonce
    end

    # Authenticates the owner accessing the engine.
    # Uses the configured authentication method from ApiKeys.configuration
    def authenticate_api_keys_owner!
      auth_method = ApiKeys.configuration.authenticate_owner_method

      if auth_method.present?
        unless respond_to?(auth_method, true)
          log_error "[ApiKeys Security] Configured owner authentication method is unavailable."
          return render_api_keys_unauthorized
        end

        send(auth_method)
        return if performed?
      end

      render_api_keys_unauthorized unless current_api_keys_owner
    end

    # Helper method to access the current owner from the host application.
    # Uses the configured method name (defaults to :current_user)
    def current_api_keys_owner
      owner_method = ApiKeys.configuration.current_owner_method

      if owner_method && respond_to?(owner_method, true)
        send(owner_method)
      else
        nil # No owner context found
      end
    end

    # Expose current_api_keys_owner as a helper method for views
    helper_method :current_api_keys_owner

    def render_api_keys_unauthorized
      render plain: "Unauthorized", status: :unauthorized
    end

    def set_api_keys_security_headers
      response.headers["Cache-Control"] = "no-store, private"
      response.headers["Pragma"] = "no-cache"
      response.headers["Referrer-Policy"] = "no-referrer"
      response.headers["X-Content-Type-Options"] = "nosniff"
      response.headers["X-Frame-Options"] = "DENY"
      response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    end

  end
end
