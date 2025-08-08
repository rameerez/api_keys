# frozen_string_literal: true

require "test_helper"
require "active_job"

module ApiKeys
  module Jobs
    class CallbacksJobTest < ApiKeys::Test
      def setup
        super
        ActiveJob::Base.queue_adapter = :test
      end

      test "executes before_authentication callback with context" do
        executed = false
        received = nil
        ApiKeys.configure { |c| c.before_authentication = ->(ctx) { executed = true; received = ctx } }

        ctx = { foo: "bar" }
        ApiKeys::Jobs::CallbacksJob.perform_now(:before_authentication, ctx)

        assert executed
        assert_equal ctx, received
      end

      test "executes after_authentication callback without args if arity 0" do
        executed = false
        ApiKeys.configure { |c| c.after_authentication = -> { executed = true } }

        ApiKeys::Jobs::CallbacksJob.perform_now(:after_authentication, { success: true })
        assert executed
      end

      test "unknown callback type is handled" do
        assert_silent do
          ApiKeys::Jobs::CallbacksJob.perform_now(:unknown, {})
        end
      end

      test "errors inside callback are logged and not raised to caller" do
        ApiKeys.configure { |c| c.after_authentication = ->(_) { raise "boom" } }
        assert_silent do
          ApiKeys::Jobs::CallbacksJob.perform_now(:after_authentication, {})
        end
      end
    end
  end
end