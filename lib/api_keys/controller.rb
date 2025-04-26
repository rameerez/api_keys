# frozen_string_literal: true

require "active_support/concern"
require_relative "authentication"       # Include authentication logic
require_relative "tenant_resolution"    # Include tenant resolution logic

module ApiKeys
  # Unified controller concern that bundles common ApiKeys functionality
  # for easy inclusion in controllers.
  #
  # Includes:
  #   - ApiKeys::Authentication (provides authenticate_api_key!, current_api_key, etc.)
  #   - ApiKeys::TenantResolution (provides current_api_tenant)
  #
  # == Usage
  #
  #   class Api::BaseController < ActionController::API
  #     include ApiKeys::Controller
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
      include ApiKeys::Authentication
      include ApiKeys::TenantResolution

      # You could add further convenience methods here if needed,
      # potentially combining logic from both included concerns.
    end

    # Add any class methods specific to this unified concern if necessary
    # module ClassMethods
    # end
  end
end
