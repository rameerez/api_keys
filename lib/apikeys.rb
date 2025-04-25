# frozen_string_literal: true

# This is the entry point to the gem.

require "rails"
require "active_record"
require "active_support/all"

require "apikeys/version"
require "apikeys/configuration"

require "apikeys/models/concerns/has_api_keys"

require "apikeys/models/api_key"

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

    # Resets the configuration to its default values.
    # Useful for testing.
    def reset_configuration!
      @configuration = Configuration.new
    end

  end
end

# TODO: Require other necessary files like configuration, engine, etc.
# require_relative "apikeys/configuration"
# require_relative "apikeys/engine"
# require_relative "apikeys/railtie" if defined?(Rails::Railtie)
