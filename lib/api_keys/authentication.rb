# frozen_string_literal: true

require "active_support/concern"
require_relative "services/authenticator"
require_relative "logging"

module ApiKeys
  # Controller concern for handling API key authentication.
  # Provides `authenticate_api_key!` method and helper methods.
  module Authentication
    extend ActiveSupport::Concern
    include ApiKeys::Logging

    included do
      # Helper methods to access the authenticated key and its owner
      helper_method :current_api_key, :current_api_owner, :current_api_user
    end

    # Returns the currently authenticated API key instance if authentication was
    # successful, otherwise returns nil.
    #
    # @return [ApiKeys::ApiKey, nil]
    def current_api_key
      @current_api_key
    end

    # Returns the owner of the currently authenticated ApiKey, if any.
    # @return [Object, nil] The polymorphic owner instance (e.g., User).
    def current_api_owner
      current_api_key&.owner
    end

    # Convenience helper: returns the owner if it's a User instance.
    # @return [User, nil]
    def current_api_user
      owner = current_api_owner
      owner if owner.is_a?(::User) # Assumes a User class exists
    end

    private

    # The core authentication method. Runs the Authenticator service.
    # If authentication fails, it renders a standard JSON error response and halts.
    # If successful, it sets @current_api_key.
    #
    # @param scope [String, Array<String>, nil] Optional scope(s) required for this action.
    def authenticate_api_key!(scope: nil)
      log_debug "[ApiKeys Auth] authenticate_api_key! started for request: #{request.uuid}"
      result = Services::Authenticator.call(request)
      log_debug "[ApiKeys Auth] Authenticator result: #{result.inspect}"

      if result.success?
        @current_api_key = result.api_key
        log_debug "[ApiKeys Auth] Authentication successful. Key ID: #{@current_api_key.id}"

        # Check required scope(s) if provided
        if scope && !check_api_key_scopes(scope)
          log_debug "[ApiKeys Auth] Scope check failed. Required: #{scope}, Key scopes: #{@current_api_key.scopes}"
          render_unauthorized(error_code: :missing_scope, message: "API key does not have the required scope(s): #{scope}")
          return # Halt chain
        end
        # Authentication successful, optionally update usage stats
        update_key_usage_stats if ApiKeys.configuration.track_requests_count
      else
        # Authentication failed
        log_debug "[ApiKeys Auth] Authentication failed. Error: #{result.error_code}, Message: #{result.message}"
        render_unauthorized(error_code: result.error_code, message: result.message)
        # Implicitly halts chain due to render
      end
    end

    # Checks if the current_api_key has the required scope(s).
    # Handles single scope string or array of scopes.
    #
    # @param required_scopes [String, Array<String>] The required scope(s).
    # @return [Boolean] True if the key has all required scopes, false otherwise.
    def check_api_key_scopes(required_scopes)
      return true unless current_api_key # Should not happen if authenticate_api_key! ran
      return true if required_scopes.blank?

      Array(required_scopes).all? do |req_scope|
        current_api_key.allows_scope?(req_scope)
      end
    end

    # Renders a standard JSON error response for authentication failures.
    #
    # @param error_code [Symbol] The error code (e.g., :invalid_token).
    # @param message [String] The error message.
    # @param status [Symbol, Integer] The HTTP status code (defaults to :unauthorized / 401).
    def render_unauthorized(error_code:, message:, status: :unauthorized)
      # Translate error code using I18n if available, otherwise use message
      # TODO: Add I18n locale file later
      error_message = I18n.t("api_keys.errors.#{error_code}", default: message) rescue message

      response_body = { error: error_code, message: error_message }
      # Add required scope info for missing_scope errors
      response_body[:required_scope] = scope if error_code == :missing_scope && defined?(scope)

      render json: response_body, status: status
    end

    # Updates the last_used_at timestamp and optionally increments requests_count.
    # This should be efficient and avoid excessive DB writes if possible.
    # Consider background jobs or batched updates for high traffic.
    def update_key_usage_stats
      return unless current_api_key

      # Use update_columns for efficiency, skipping validations/callbacks
      updates = { last_used_at: Time.current }
      if ApiKeys.configuration.track_requests_count
        # Use increment_counter for atomic updates if available and suitable
        # Or fallback to update_columns with an increment expression
        # Note: This simplistic approach might have race conditions at high concurrency.
        # Consider database-specific atomic increments or background jobs.
        current_api_key.class.increment_counter(:requests_count, current_api_key.id)
        # If not using increment_counter, you might do:
        # updates[:requests_count] = (current_api_key.requests_count || 0) + 1
        # current_api_key.update_columns(updates) # Requires fetching count first
      else
        current_api_key.update_column(:last_used_at, updates[:last_used_at])
      end

    rescue ActiveRecord::ActiveRecordError => e
      Rails.logger.error "[ApiKeys] Failed to update usage stats for key #{current_api_key.id}: #{e.message}" if defined?(Rails.logger)
      # Don't let stat update failures break the request
    end

  end
end
