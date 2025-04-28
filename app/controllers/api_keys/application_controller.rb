# frozen_string_literal: true

module ApiKeys
  # Base controller for the ApiKeys engine.
  # Inherits from the host application's configured controller
  # (defaults to ::ApplicationController).
  # Includes common engine functionality.
  class ApplicationController < ApiKeys::Engine.config.parent_controller.constantize
    # Protect from forgery if the parent controller does
    # This ensures CSRF protection behaves consistently with the host app.
    protect_from_forgery with: :exception if respond_to?(:protect_from_forgery)

    # Include the main controller concern which bundles authentication and tenant resolution
    include ApiKeys::Controller

    # Ensure user is authenticated for all actions within this engine
    # IMPORTANT: This assumes the host application provides a `current_user` method
    # and potentially a `authenticate_user!` method (like Devise).
    # You might need to adjust this based on the host app's authentication system.
    before_action :authenticate_api_keys_user!

    private

    # Placeholder method to authenticate the user accessing the engine.
    # Relies on the host application providing `authenticate_user!` and `current_user`.
    # Developers might need to override this in their application or configure
    # the authentication method if it differs from standard Devise/similar patterns.
    def authenticate_api_keys_user!
      # Try common authentication methods
      if defined?(authenticate_user!)
        authenticate_user!
      elsif defined?(require_login)
        require_login # Common in Sorcery
      else
        # Fallback or raise error if no known authentication method is found
        unless current_api_keys_user
          # Redirect or render error if no user context is available
          # Choose the appropriate action based on expected host app behavior
          redirect_to main_app.root_path, alert: "You need to sign in or sign up before continuing." rescue render plain: "Unauthorized", status: :unauthorized
        end
      end
    end

    # Helper method to access the current user from the host application.
    # Assumes the host app provides `current_user`.
    def current_api_keys_user
      # Use `super` if the parent controller defines `current_user`
      # Otherwise, try calling `current_user` directly on self if it's mixed in.
      if defined?(super)
        super
      elsif defined?(current_user)
        current_user
      else
        nil # No user context found
      end
    end

    # Expose current_api_keys_user as a helper method for views
    helper_method :current_api_keys_user

  end
end
