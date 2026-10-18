# frozen_string_literal: true

require "active_job"
require "active_support/core_ext/numeric/time"
require_relative "../models/api_key"
require_relative "../logging"

module ApiKeys
  module Jobs
    # Background job to update API key usage statistics (last_used_at, requests_count).
    # Enqueued by the Authentication concern after a successful request.
    #
    # With `refusal_code:` it records refused-but-identified traffic instead
    # (last_refused_at, last_refusal_code, refusals_count). The two halves never
    # share a write: a refusal is not a use, so it can never move last_used_at
    # or requests_count, whatever the code says.
    class UpdateStatsJob < ActiveJob::Base
      include ApiKeys::Logging # Include logging helpers

      MAX_FUTURE_CLOCK_SKEW = 5.minutes

      # Resolve the configured queue for each job so initializer changes apply.
      queue_as { ApiKeys.configuration.stats_job_queue }

      # Perform the database updates for the given ApiKey.
      #
      # @param api_key_id [Integer, String] The ID of the ApiKey to update.
      # @param timestamp [Time] The timestamp of the request (when it was authenticated).
      # @param refusal_code [String, nil] Present when the request was refused
      #   after the key was identified; one of ApiKeys::ApiKey::REFUSAL_CODES.
      def perform(api_key_id, timestamp, refusal_code: nil)
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

        # Any refusal marker at all, even a blank or unrecognized one, takes the
        # refusal branch: the usage branch runs only for a genuine success.
        unless refusal_code.nil?
          record_refusal(api_key, timestamp, refusal_code)
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

      private

      # Stamps a refusal. An installation that has not run
      # `rails generate api_keys:add_key_activity` yet skips it quietly, so a
      # deploy that ships code before the migration never fails these jobs.
      def record_refusal(api_key, timestamp, refusal_code)
        unless ApiKey.refusal_stats_columns?
          log_debug "[ApiKeys::Jobs::UpdateStatsJob] Refusal stats columns are missing; skipping. " \
                    "Run: rails generate api_keys:add_key_activity && rails db:migrate"
          return
        end

        code = refusal_code.to_s
        unless ApiKey::REFUSAL_CODES.include?(code)
          log_warn "[ApiKeys::Jobs::UpdateStatsJob] Ignored an unrecognized refusal code for ApiKey ID: #{api_key.id}."
          return
        end

        # Same ordering guard as last_used_at: an older refusal processed late
        # cannot overwrite a newer one, and the code always matches its timestamp.
        ApiKey
          .where(id: api_key.id)
          .where("last_refused_at IS NULL OR last_refused_at < ?", timestamp)
          .update_all(last_refused_at: timestamp, last_refusal_code: code)

        # Counted under the same switch as requests_count, which is also the only
        # mode in which no refusal is debounced away, so the count is exact.
        ApiKey.increment_counter(:refusals_count, api_key.id) if ApiKeys.configuration.track_requests_count
      end
    end
  end
end
