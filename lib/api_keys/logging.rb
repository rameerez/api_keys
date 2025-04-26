# frozen_string_literal: true

module ApiKeys
  # Shared logging utilities for the ApiKeys gem.
  module Logging
    private

    # Helper for conditional debug logging based on configuration.
    #
    # @param message [String] The message to log.
    def log_debug(message)
      # Only log if debug_logging is enabled and a logger is available
      if ApiKeys.configuration.debug_logging && logger
        logger.debug(message)
      end
    end

    # Helper for conditional warning logging.
    # Warnings are logged regardless of debug flag, if logger available.
    #
    # @param message [String] The message to log.
    def log_warn(message)
      logger.warn(message) if logger
    end

    # Provides access to the logger instance (Rails.logger if defined).
    #
    # @return [Logger, nil] The logger instance or nil.
    def logger
      # Memoize the logger instance for performance
      @_api_keys_logger ||= defined?(Rails) ? Rails.logger : nil
    end
  end
end
