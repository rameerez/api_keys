# frozen_string_literal: true

require "active_support/concern"
require_relative "services/authenticator"
require_relative "logging"
require_relative "jobs/update_stats_job"
require_relative "jobs/callbacks_job"

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

    # The core authentication method.
    def authenticate_api_key!(scope: nil)
      log_debug "[ApiKeys Auth] authenticate_api_key! started for request: #{request.uuid}"

      # Enqueue before_authentication callback asynchronously
      enqueue_callback(:before_authentication, { request_uuid: request.uuid })

      # Perform synchronous authentication
      result = Services::Authenticator.call(request)
      log_debug "[ApiKeys Auth] Authenticator result: #{result.inspect}"

      # Prepare context for after_authentication callback
      after_auth_context = {
        success: result.success?,
        error_code: result.error_code,
        message: result.message,
        api_key_id: result.api_key&.id # Pass ID only, not the full object
      }

      if result.success?
        @current_api_key = result.api_key
        log_debug "[ApiKeys Auth] Authentication successful. Key ID: #{@current_api_key.id}"

        if scope && !check_api_key_scopes(scope)
          log_debug "[ApiKeys Auth] Scope check failed. Required: #{scope}, Key scopes: #{@current_api_key.scopes}"
          # Add required scope info to context before rendering/enqueueing
          after_auth_context[:required_scope_check] = { required: scope, passed: false }
          render_unauthorized(error_code: :missing_scope, message: "API key does not have the required scope(s): #{scope}", required_scope: scope)
        else
          after_auth_context[:required_scope_check] = { required: scope, passed: true } if scope
          # Authentication and scope check successful, enqueue stats update
          update_key_usage_stats # Enqueues UpdateStatsJob
        end
      else
        # Authentication failed
        log_debug "[ApiKeys Auth] Authentication failed. Error: #{result.error_code}, Message: #{result.message}"
        render_unauthorized(error_code: result.error_code, message: result.message)
      end

      # Enqueue after_authentication callback asynchronously regardless of success/failure
      enqueue_callback(:after_authentication, after_auth_context)
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
    def render_unauthorized(error_code:, message:, status: :unauthorized, required_scope: nil)
      error_message = I18n.t("api_keys.errors.#{error_code}", default: message) rescue message
      response_body = { error: error_code, message: error_message }
      response_body[:required_scope] = required_scope if error_code == :missing_scope && required_scope
      render json: response_body, status: status
    end

    # Enqueues the UpdateStatsJob.
    def update_key_usage_stats
      return unless current_api_key

      # Check ActiveJob configuration and warn if using suboptimal adapters
      adapter = ActiveJob::Base.queue_adapter
      if adapter.is_a?(ActiveJob::QueueAdapters::InlineAdapter)
        log_warn "[ApiKeys] ActiveJob adapter is :inline. ApiKey stats updates will run synchronously within the request cycle, potentially impacting performance."
      elsif adapter.is_a?(ActiveJob::QueueAdapters::AsyncAdapter)
        log_warn "[ApiKeys] ActiveJob adapter is :async. ApiKey stats updates run in-process and may be lost on application restarts. Configure a persistent backend (Sidekiq, GoodJob, SolidQueue, etc.) for reliability."
      end

      begin
        timestamp = Time.current # Capture time once for the job
        log_debug "[ApiKeys Auth] Enqueuing UpdateStatsJob for ApiKey ID: #{current_api_key.id} at #{timestamp}"
        ApiKeys::Jobs::UpdateStatsJob.perform_later(current_api_key.id, timestamp)
      rescue StandardError => e
        log_error "[ApiKeys Auth] Failed to enqueue UpdateStatsJob for key #{current_api_key.id}: #{e.message}"
      end
    end

    # Helper to safely enqueue callback jobs.
    def enqueue_callback(callback_type, context)
      begin
        log_debug "[ApiKeys Auth] Enqueuing CallbacksJob for type: #{callback_type} with context: #{context.inspect}"
        ApiKeys::Jobs::CallbacksJob.perform_later(callback_type, context)
      rescue StandardError => e
        log_error "[ApiKeys Auth] Failed to enqueue CallbacksJob for type #{callback_type}: #{e.message}"
        # Don't fail the request if callback enqueueing fails
      end
    end

  end
end
