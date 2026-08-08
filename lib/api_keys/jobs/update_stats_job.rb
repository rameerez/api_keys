# frozen_string_literal: true

require "active_job"
require "active_support/core_ext/numeric/time"
require_relative "../models/api_key"
require_relative "../logging"

module ApiKeys
  module Jobs
    # Background job to update API key usage statistics (last_used_at, requests_count).
    # Enqueued by the Authentication concern after a successful request.
    class UpdateStatsJob < ActiveJob::Base
      include ApiKeys::Logging # Include logging helpers

      MAX_FUTURE_CLOCK_SKEW = 5.minutes

      # Resolve the configured queue for each job so initializer changes apply.
      queue_as { ApiKeys.configuration.stats_job_queue }

      # Perform the database updates for the given ApiKey.
      #
      # @param api_key_id [Integer, String] The ID of the ApiKey to update.
      # @param timestamp [Time] The timestamp of the request (when it was authenticated).
      def perform(api_key_id, timestamp)
        api_key = ApiKey.find_by(id: api_key_id)

        unless api_key
          log_warn "[ApiKeys::Jobs::UpdateStatsJob] ApiKey not found with ID: #{api_key_id}. Skipping stats update."
          return
        end

        unless timestamp.respond_to?(:to_time)
          log_warn "[ApiKeys::Jobs::UpdateStatsJob] Invalid timestamp for ApiKey ID: #{api_key_id}. Skipping stats update."
          return
        end
        timestamp = timestamp.to_time

        if timestamp > Time.current + MAX_FUTURE_CLOCK_SKEW
          log_warn "[ApiKeys::Jobs::UpdateStatsJob] Rejected a timestamp too far in the future."
          return
        end

        log_debug "[ApiKeys::Jobs::UpdateStatsJob] Updating stats for ApiKey ID: #{api_key_id}"

        # Jobs may execute out of order. Update only when this event is newer so
        # last_used_at can never regress to an earlier request timestamp.
        ApiKey
          .where(id: api_key.id)
          .where("last_used_at IS NULL OR last_used_at < ?", timestamp)
          .update_all(last_used_at: timestamp)

        # Conditionally increment requests_count if configured
        if ApiKeys.configuration.track_requests_count
          # Use increment_counter for atomic updates
          ApiKey.increment_counter(:requests_count, api_key.id)
          log_debug "[ApiKeys::Jobs::UpdateStatsJob] Incremented requests_count for ApiKey ID: #{api_key_id}"
        end

        log_debug "[ApiKeys::Jobs::UpdateStatsJob] Finished updating stats for ApiKey ID: #{api_key_id}"

      rescue ActiveRecord::ActiveRecordError => error
        # Log error but don't automatically retry unless configured to do so.
        # Frequent stats updates might tolerate occasional failures better than endless retries.
        log_error "[ApiKeys::Jobs::UpdateStatsJob] Failed to update stats for ApiKey ID: #{api_key_id} (#{error.class})."
        # Depending on ActiveJob adapter, specific retry logic might be needed here
        # or configured globally. For now, just log.
      rescue StandardError => error
        log_error "[ApiKeys::Jobs::UpdateStatsJob] Unexpected error processing ApiKey ID: #{api_key_id} (#{error.class})."
        # Consider re-raising or using a dead-letter queue strategy depending on job system
      end
    end
  end
end
