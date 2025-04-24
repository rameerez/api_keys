# frozen_string_literal: true

# This is the entry point to the gem.

require "rails"
require "active_record"
require "active_support/all"

require "apikeys/version"
require "apikeys/configuration"

# Rails integration
require "apikeys/engine" if defined?(Rails)

# Main module that serves as the primary interface to the gem.
# Most methods here delegate to Configuration, which is the single source of truth for all config in the initializer
module Apikeys
  # Custom error classes
  class Error < StandardError; end

  class << self
    attr_writer :configuration

    def configuration
      @configuration ||= Configuration.new
    end

    # Configure the gem with a block (main entry point)
    def configure
      yield(configuration)
    end

  end
end
