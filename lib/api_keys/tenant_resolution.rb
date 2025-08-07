# frozen_string_literal: true

require "active_support/concern"

module ApiKeys
  # Controller concern to resolve and provide access to the tenant
  # associated with the currently authenticated API key.
  module TenantResolution
    extend ActiveSupport::Concern

    included do
      helper_method :current_api_tenant

      # Alias for convenience and explicitness
      alias_method :current_api_key_tenant, :current_api_tenant
      alias_method :current_api_account, :current_api_tenant
      alias_method :current_api_key_account, :current_api_tenant
      alias_method :current_api_owner, :current_api_tenant
      alias_method :current_api_key_owner, :current_api_tenant
    end

    # Returns the tenant associated with the current API key.
    # Uses the configured `tenant_resolver` lambda.
    # Returns nil if no key is authenticated, no owner exists,
    # or the resolver returns nil.
    #
    # @return [Object, nil] The resolved tenant object, or nil.
    def current_api_tenant
      return @current_api_tenant if defined?(@current_api_tenant)
      return nil unless current_api_key # Requires Authentication concern to be included first

      resolver = ApiKeys.configuration.tenant_resolver
      @current_api_tenant = resolver&.call(current_api_key)
    rescue StandardError => e
      # Log error but don't break the request if resolver fails
      if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
        Rails.logger.error "[ApiKeys] Tenant resolution failed: #{e.message}"
      end
      @current_api_tenant = nil
    end
  end
end
