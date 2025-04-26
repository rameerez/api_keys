# frozen_string_literal: true

require "active_support/concern"
require_relative "authentication"       # Include authentication logic
require_relative "tenant_resolution"    # Include tenant resolution logic

module Apikeys
  # Unified controller concern that bundles common Apikeys functionality
  # for easy inclusion in controllers.
  #
  # Includes:
  #   - Apikeys::Authentication (provides authenticate_api_key!, current_api_key, etc.)
  #   - Apikeys::TenantResolution (provides current_api_tenant)
  #
  # == Usage
  #
  #   class Api::BaseController < ActionController::API
  #     include Apikeys::Controller
  #
  #     before_action :authenticate_api_key!
  #
  #     def show
  #       # Access helpers provided by the included concerns
  #       key = current_api_key
  #       owner = current_api_owner
  #       tenant = current_api_tenant
  #       # ...
  #     end
  #   end
  #
  module Controller
    extend ActiveSupport::Concern

    included do
      # Bring in the functionality from the specific concerns
      include Apikeys::Authentication
      include Apikeys::TenantResolution

      # Alias for convenience and explicitness
      alias_method :current_api_key_tenant, :current_api_tenant
      alias_method :current_api_account, :current_api_tenant
      alias_method :current_api_key_account, :current_api_tenant
      alias_method :current_api_owner, :current_api_tenant
      alias_method :current_api_key_owner, :current_api_tenant

      # You could add further convenience methods here if needed,
      # potentially combining logic from both included concerns.
    end

    # Add any class methods specific to this unified concern if necessary
    # module ClassMethods
    # end
  end
end
