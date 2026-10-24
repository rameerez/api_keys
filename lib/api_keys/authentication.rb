# frozen_string_literal: true

require "active_support/cache"
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

    # Failures where the credential is valid but the request context is refused.
    # The key itself is fine, so these answer 403 rather than 401 — the same
    # distinction `:missing_scope` already makes.
    FORBIDDEN_ERROR_CODES = %i[origin_not_allowed ip_not_allowed restriction_misconfigured].freeze
    # Names the per-key reservation that lets one stats job per kind be
    # enqueued within a debounce interval (see reserve_stats_enqueue?).
    STATS_ENQUEUE_NAMESPACE = "api_keys:v1:stats_enqueue"
    # The methods that read. Every other method writes. RFC 9110 §9.2.1 also
    # names OPTIONS and TRACE safe, but an API action does not serve them,
    # so they count as writes and need the stricter scope.
    READ_METHODS = %w[GET HEAD].freeze

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

    alias_method :current_api_key_owner, :current_api_owner

    # Convenience helper: returns the owner if it's a User instance.
    # @return [User, nil]
    def current_api_user
      owner = current_api_owner
      owner if defined?(::User) && owner.is_a?(::User)
    end

    private

    # The core authentication method.
    #
    # @param scope [String, Array<String>, Hash, nil] The scope(s) the key
    #   needs. A Hash names them by HTTP method, in one line:
    #   `scope: { read: "read", write: "write" }` asks GET and HEAD for the
    #   read scope and every other method for the write scope.
    def authenticate_api_key!(scope: nil)
      scope = scope_for_request_method(scope) if scope.is_a?(Hash)
      @current_api_key = nil
      remove_instance_variable(:@current_api_tenant) if instance_variable_defined?(:@current_api_tenant)
      log_debug "[ApiKeys Auth] authenticate_api_key! started for request: #{request.uuid}"

      # Enqueue before_authentication callback asynchronously
      enqueue_callback(:before_authentication, { request_uuid: request.uuid })

      # Perform synchronous authentication
      result = Services::Authenticator.call(request)
      log_debug "[ApiKeys Auth] Authentication result: success=#{result.success?}, error_code=#{result.error_code || 'none'}"

      # Prepare context for after_authentication callback
      after_auth_context = {
        success: result.success?,
        error_code: result.error_code,
        api_key_id: result.api_key&.id # Pass ID only, not the full object
      }

      if result.success?
        @current_api_key = result.api_key
        log_debug "[ApiKeys Auth] Authentication successful. Key ID: #{@current_api_key.id}"

        if scope && !check_api_key_scopes(scope)
          log_debug "[ApiKeys Auth] Scope check failed for key ID #{@current_api_key.id}."
          # Add required scope info to context before rendering/enqueueing
          after_auth_context[:required_scope_check] = { required: scope, passed: false }
          after_auth_context[:success] = false
          after_auth_context[:error_code] = :missing_scope
          refused_key = @current_api_key
          @current_api_key = nil
          render_unauthorized(
            error_code: :missing_scope,
            message: "API key does not have the required scope(s): #{scope}",
            status: :forbidden,
            required_scope: scope
          )
          record_key_refusal(refused_key, :missing_scope)
        elsif !api_key_trusted?(@current_api_key)
          log_debug "[ApiKeys Auth] Trust check failed for key ID #{@current_api_key.id}."
          after_auth_context[:required_scope_check] = { required: scope, passed: true } if scope
          after_auth_context[:success] = false
          after_auth_context[:error_code] = :untrusted_key
          refused_key = @current_api_key
          @current_api_key = nil
          render_unauthorized(
            error_code: :untrusted_key,
            message: "API key is no longer trusted: the person behind it no longer stands behind it",
            status: :forbidden
          )
          record_key_refusal(refused_key, :untrusted_key)
        else
          after_auth_context[:required_scope_check] = { required: scope, passed: true } if scope
          # Authentication and scope check successful, enqueue stats update
          update_key_usage_stats # Enqueues UpdateStatsJob
        end
      else
        # Authentication failed
        log_debug "[ApiKeys Auth] Authentication failed. Error: #{result.error_code}, Message: #{result.message}"
        status = FORBIDDEN_ERROR_CODES.include?(result.error_code) ? :forbidden : :unauthorized
        render_unauthorized(error_code: result.error_code, message: result.message, status: status)
        # Only identified refusals carry a key; lookup failures have none to stamp.
        record_key_refusal(result.api_key, result.error_code) if result.api_key
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
      return false unless current_api_key
      return true if required_scopes.blank?

      Array(required_scopes).all? do |req_scope|
        current_api_key.allows_scope?(req_scope)
      end
    end

    # Whether this request reads (GET or HEAD).
    def reading_request?
      READ_METHODS.include?(request.request_method)
    end

    # The scope of `scope: { read:, write: }` for this request's method. Both
    # are required, so a forgotten one never leaves its requests unchecked.
    # A value of nil asks for no scope.
    def scope_for_request_method(scopes)
      scopes = scopes.to_h.transform_keys(&:to_sym)
      unless scopes.keys.sort == %i[read write]
        raise ArgumentError, "scope: by HTTP method takes exactly { read: ..., write: ... }"
      end

      reading_request? ? scopes[:read] : scopes[:write]
    end

    # Whether the person behind the key still stands behind it, as the host's
    # `config.trusted_key_check` answers. Without a check, every valid key is
    # trusted. An error in the check is not rescued: the request fails, and
    # never passes as trusted.
    def api_key_trusted?(api_key)
      check = ApiKeys.configuration.trusted_key_check
      check.nil? || check.call(api_key) ? true : false
    end

    # Renders a standard JSON error response for authentication failures.
    # Every refusal of the gem renders here, so a host that overrides it
    # renders them all in its own error shape.
    def render_unauthorized(error_code:, message:, status: :unauthorized, required_scope: nil)
      error_message = I18n.t("api_keys.errors.#{error_code}", default: message) rescue message
      response_body = { error: error_code, message: error_message }
      response_body[:required_scope] = required_scope if error_code == :missing_scope && required_scope
      render json: response_body, status: status
    end

    # Enqueues the UpdateStatsJob.
    def update_key_usage_stats
      # Return early if async operations are globally disabled
      return unless ApiKeys.configuration.enable_async_operations
      return unless current_api_key

      if stats_update_debounced?(current_api_key.last_used_at)
        log_debug "[ApiKeys Auth] Skipping a recently recorded last-used update for ApiKey ID: #{current_api_key.id}"
        return
      end
      unless reserve_stats_enqueue?(:used, current_api_key.id)
        log_debug "[ApiKeys Auth] Skipping a last-used update already enqueued for ApiKey ID: #{current_api_key.id}"
        return
      end

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
        # Active Job answers false (instead of raising) when the adapter
        # failed to enqueue; either way the reservation is freed.
        unless ApiKeys::Jobs::UpdateStatsJob.perform_later(current_api_key.id, timestamp)
          release_stats_enqueue(:used, current_api_key.id)
          log_error "[ApiKeys Auth] UpdateStatsJob was not enqueued for key #{current_api_key.id}."
        end
      rescue StandardError => error
        release_stats_enqueue(:used, current_api_key.id)
        log_error "[ApiKeys Auth] Failed to enqueue UpdateStatsJob for key #{current_api_key.id} (#{error.class})."
      end
    end

    # Enqueues the refusal half of UpdateStatsJob for a key that presented its
    # real token and was refused by a policy. It moves only last_refused_at,
    # last_refusal_code and (with track_requests_count) refusals_count; a
    # refusal never counts as a use. Debounced exactly like last_used_at, so a
    # client hammering a refused key costs no more writes than a working one.
    # Never raises: the refusal response has already been rendered.
    def record_key_refusal(api_key, error_code)
      return unless ApiKeys.configuration.enable_async_operations
      return unless api_key&.id

      code = error_code.to_s
      return unless ApiKeys::ApiKey::REFUSAL_CODES.include?(code)
      return unless ApiKeys::ApiKey.refusal_stats_columns?

      if stats_update_debounced?(api_key.last_refused_at)
        log_debug "[ApiKeys Auth] Skipping a recently recorded refusal update for ApiKey ID: #{api_key.id}"
        return
      end
      unless reserve_stats_enqueue?(:refused, api_key.id)
        log_debug "[ApiKeys Auth] Skipping a refusal update already enqueued for ApiKey ID: #{api_key.id}"
        return
      end

      begin
        # Active Job answers false (instead of raising) when the adapter
        # failed to enqueue; either way the reservation is freed.
        unless ApiKeys::Jobs::UpdateStatsJob.perform_later(api_key.id, Time.current, refusal_code: code)
          release_stats_enqueue(:refused, api_key.id)
          log_error "[ApiKeys Auth] A refusal stats update was not enqueued for key #{api_key.id}."
        end
      rescue StandardError
        release_stats_enqueue(:refused, api_key.id)
        raise
      end
    rescue StandardError => error
      log_error "[ApiKeys Auth] Failed to enqueue a refusal stats update for key #{api_key&.id} (#{error.class})."
    end

    def stats_update_debounced?(last_recorded_at)
      seconds = stats_debounce_seconds
      return false unless seconds && last_recorded_at

      last_recorded_at >= Time.current - seconds
    end

    # The debounce interval in seconds, or nil when every request must be
    # recorded (exact counting with track_requests_count, or no interval).
    def stats_debounce_seconds
      config = ApiKeys.configuration
      return nil if config.track_requests_count

      interval = config.stats_update_interval
      seconds = interval.to_f if interval.respond_to?(:to_f)
      seconds&.finite? && seconds.positive? ? seconds : nil
    end

    # The persisted timestamp only debounces once a worker has written it, so
    # a burst of requests arriving before that would each enqueue a job. With
    # a shared cache, the first request in an interval reserves the enqueue
    # for its key and kind (:used or :refused) atomically, with
    # `write(..., unless_exist: true, expires_in: interval)`, and the rest of
    # the burst is skipped.
    #
    # A request is skipped only when the reservation is confirmed to exist:
    # the write answered false (not stored) and the key is then present.
    # Stores also answer false or nil when the write itself failed (Redis
    # returns nil on a handled error, Memcached false), and suppressing the
    # job then would lose statistics silently. So a nil answer, an absent
    # key, or any error enqueues. It also enqueues when debouncing does not
    # apply or there is no shared cache (`NullStore`, or no Rails.cache):
    # the persisted timestamp is then the only debounce, as before 0.6.0.
    def reserve_stats_enqueue?(kind, api_key_id)
      seconds = stats_debounce_seconds
      return true unless seconds

      cache = stats_enqueue_cache
      return true unless cache

      key = stats_enqueue_key(kind, api_key_id)
      written = cache.write(key, true, unless_exist: true, expires_in: seconds)
      return true unless written == false

      cache.exist?(key) ? false : true
    rescue StandardError => error
      log_debug "[ApiKeys Auth] Stats enqueue reservation unavailable (#{error.class}); relying on the persisted timestamp."
      true
    end

    # Frees a reservation whose job could not be enqueued, so the next
    # request can try again.
    def release_stats_enqueue(kind, api_key_id)
      return unless stats_debounce_seconds

      stats_enqueue_cache&.delete(stats_enqueue_key(kind, api_key_id))
    rescue StandardError
      nil
    end

    def stats_enqueue_key(kind, api_key_id)
      "#{STATS_ENQUEUE_NAMESPACE}:#{kind}:#{api_key_id}"
    end

    # A cache every process shares can deduplicate; NullStore remembers nothing.
    def stats_enqueue_cache
      cache = Rails.cache if defined?(Rails) && Rails.respond_to?(:cache)
      return nil if cache.nil? || cache.is_a?(ActiveSupport::Cache::NullStore)

      cache
    end

    # Helper to safely enqueue callback jobs.
    def enqueue_callback(callback_type, context)
      # Return early if async operations are globally disabled
      return unless ApiKeys.configuration.enable_async_operations

      # Determine the configuration method name (e.g., :before_authentication)
      config_method = callback_type # Assuming callback_type directly matches config accessor

      # Get the configured proc
      callback_proc = ApiKeys.configuration.public_send(config_method)

      # Skip enqueueing if the callback is the default empty proc
      if callback_proc == ApiKeys::Configuration::DEFAULT_CALLBACK
        log_debug "[ApiKeys Auth] Skipping enqueue for default empty callback: #{callback_type}"
        return
      end

      # Proceed with enqueueing if it's a configured callback
      begin
        log_debug "[ApiKeys Auth] Enqueuing callback job for type: #{callback_type}"
        ApiKeys::Jobs::CallbacksJob.perform_later(callback_type, context)
      rescue StandardError => error
        log_error "[ApiKeys Auth] Failed to enqueue CallbacksJob for type #{callback_type} (#{error.class})."
        # Don't fail the request if callback enqueueing fails
      end
    end

  end
end
