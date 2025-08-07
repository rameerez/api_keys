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
    end
  end
end