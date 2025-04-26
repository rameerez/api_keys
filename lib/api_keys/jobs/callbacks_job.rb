# frozen_string_literal: true

require "active_job"
require_relative "../logging"
require_relative "../configuration" # Access configuration for callbacks

module ApiKeys
  module Jobs
    # Background job to execute configured lifecycle callbacks asynchronously.
    class CallbacksJob < ActiveJob::Base
      include ApiKeys::Logging

      # Use the queue name specified in the configuration (evaluated at load time)
      queue_as ApiKeys.configuration.callbacks_job_queue

      # Executes the appropriate callback based on the type.
      #
      # @param callback_type [Symbol] :before_authentication or :after_authentication
      # @param context [Hash] Serializable context data for the callback.
      def perform(callback_type, context = {})
        config = ApiKeys.configuration

        case callback_type
        when :before_authentication
          execute_callback(config.before_authentication, context)
        when :after_authentication
          execute_callback(config.after_authentication, context)
        else
          log_warn "[ApiKeys::Jobs::CallbacksJob] Unknown callback type: #{callback_type}"
        end
      rescue StandardError => e
        log_error "[ApiKeys::Jobs::CallbacksJob] Error executing callback #{callback_type} with context #{context.inspect}: #{e.class}: #{e.message}
#{e.backtrace.join("
")}"
        # Avoid retrying callback errors by default, as the original request succeeded.
        # Depending on callback importance, users might configure retries separately.
      end

      private

      # Safely executes a user-provided callback lambda.
      #
      # @param callback_proc [Proc, Lambda] The configured callback.
      # @param context [Hash] The context data to pass.
      def execute_callback(callback_proc, context)
        unless callback_proc.is_a?(Proc)
          log_debug "[ApiKeys::Jobs::CallbacksJob] Callback is not a Proc, skipping execution."
          return
        end

        arity = callback_proc.arity
        log_debug "[ApiKeys::Jobs::CallbacksJob] Executing callback with arity #{arity}"

        begin
          if arity == 1 || arity < 0 # Handle procs accepting one arg or variable args (*args)
            callback_proc.call(context)
          elsif arity == 0 # Handle procs accepting no args
            callback_proc.call
          else
            log_warn "[ApiKeys::Jobs::CallbacksJob] Callback has unexpected arity (#{arity}). Expected 0 or 1 argument (context hash). Skipping execution."
          end
        rescue StandardError => e
          # Log the specific error from the user's callback code
          raise # Re-raise to be caught by the main perform rescue block for logging
        end
      end
    end
  end
end
