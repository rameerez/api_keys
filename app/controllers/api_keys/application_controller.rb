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

    # Ensure the owner is authenticated for all actions within this engine
    # This uses the configured authentication method (defaults to authenticate_user!)
    before_action :authenticate_api_keys_owner!

    private

    # Authenticates the owner accessing the engine.
    # Uses the configured authentication method from ApiKeys.configuration
    def authenticate_api_keys_owner!
      auth_method = ApiKeys.configuration.authenticate_owner_method

      # Try to call the configured authentication method
      if auth_method && respond_to?(auth_method, true)
        send(auth_method)
      elsif auth_method && defined?(auth_method)
        send(auth_method)
      else
        # Fallback: check if owner is present
        unless current_api_keys_owner
          redirect_to main_app.root_path, alert: "You need to sign in before continuing." rescue render plain: "Unauthorized", status: :unauthorized
        end
      end
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

  end
end
