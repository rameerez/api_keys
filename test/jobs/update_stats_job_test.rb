# frozen_string_literal: true

require "test_helper"
require "active_job"

module ApiKeys
  module Jobs
    class UpdateStatsJobTest < ApiKeys::Test
      def setup
        super
        ActiveJob::Base.queue_adapter = :test
      end

      test "updates last_used_at and increments requests_count when configured" do
        ApiKeys.configure { |c| c.track_requests_count = true }
        user = User.create!(name: "Stats User")
        key = ApiKeys::ApiKey.create!(owner: user, name: "Stats Key")
        t = Time.current

        ApiKeys::Jobs::UpdateStatsJob.perform_now(key.id, t)

        key.reload
        assert_in_delta t.to_f, key.last_used_at.to_f, 1
        assert_equal 1, key.requests_count
      end

      test "updates last_used_at without increment when tracking disabled" do
        ApiKeys.configure { |c| c.track_requests_count = false }
        user = User.create!(name: "Stats User 2")
        key = ApiKeys::ApiKey.create!(owner: user, name: "Stats Key 2")
        t = Time.current

        ApiKeys::Jobs::UpdateStatsJob.perform_now(key.id, t)

        key.reload
        assert_in_delta t.to_f, key.last_used_at.to_f, 1
        assert_equal 0, key.requests_count
      end

      test "no-op when key not found" do
        assert_silent do
          ApiKeys::Jobs::UpdateStatsJob.perform_now(999_999, Time.current)
        end
      end

      test "out-of-order jobs never move last_used_at backwards" do
        user = User.create!(name: "Ordered Stats User")
        key = ApiKeys::ApiKey.create!(owner: user, name: "Ordered Stats Key")
        newest = Time.current
        oldest = 1.hour.ago

        ApiKeys::Jobs::UpdateStatsJob.perform_now(key.id, newest)
        ApiKeys::Jobs::UpdateStatsJob.perform_now(key.id, oldest)

        assert_in_delta newest.to_f, key.reload.last_used_at.to_f, 1
      end

      test "future timestamps cannot poison usage statistics" do
        user = User.create!(name: "Future Stats User")
        key = ApiKeys::ApiKey.create!(owner: user, name: "Future Stats Key")
        ApiKeys.configuration.track_requests_count = true

        ApiKeys::Jobs::UpdateStatsJob.perform_now(key.id, 1.day.from_now)

        key.reload
        assert_nil key.last_used_at
        assert_equal 0, key.requests_count
      end

      test "queue name is resolved from current configuration at enqueue time" do
        ApiKeys.configuration.stats_job_queue = :api_key_security

        assert_equal "api_key_security", ApiKeys::Jobs::UpdateStatsJob.new.queue_name
      end
    end
  end
end
