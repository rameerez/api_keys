# frozen_string_literal: true

# This is the entry point to the gem.

# Global requires that don't depend on ApiKeys module structure
require "rails"
require "active_record"
require "active_support/all" # For ActiveSupport::SecurityUtils, etc. used in Configuration

# --------- Core ApiKeys Module Definition ---------
# Define the ApiKeys module itself and its primary interface methods early.
# This ensures that ApiKeys.configuration and ApiKeys.configure are available
# when other gem files are loaded and potentially use them at load time.
module ApiKeys
  # Custom error classes
  class Error < StandardError; end

  class << self
    attr_writer :configuration

    # Provides access to the gem's configuration.
    # Initializes with default settings if not already configured.
    # Note: ApiKeys::Configuration class must be loaded before this method
    # is called in a way that triggers instantiation (e.g. first call).
    def configuration
      # Ensure @configuration is initialized with an instance of ApiKeys::Configuration.
      # The ApiKeys::Configuration class itself is defined in 'api_keys/configuration.rb'.
      @configuration ||= ::ApiKeys::Configuration.new
    end

    # Main configuration block for the gem.
    # Example:
    #   ApiKeys.configure do |config|
    #     config.token_prefix = "my_app_"
    #   end
    def configure
      yield(configuration)
    end

    # Resets the configuration to its default values.
    # Useful primarily for testing environments.
    def reset_configuration!
      @configuration = ::ApiKeys::Configuration.new
    end
  end
end

# --------- Gem Component Requires ---------
# Order is important here.
# 1. Version: Typically first.
# 2. Configuration class: Needed by ApiKeys.configuration method.
# 3. Other components: Controllers, models, engine, etc., which might use the configuration.

require "api_keys/version"
require "api_keys/configuration" # Defines the ApiKeys::Configuration class

# Files that might depend on ApiKeys.configuration being available
require "api_keys/controller" # This can lead to loading jobs, etc.
require "api_keys/models/concerns/has_api_keys"
require "api_keys/models/api_key"

# Rails integration (Engine)
# The Engine might also access ApiKeys.configuration during its initialization.
require "api_keys/engine" if defined?(Rails)

# Consider if a Railtie is needed and where its require should go.
# If it also needs ApiKeys.configuration, it should be after the main module definition
# and after api_keys/configuration.
# require "api_keys/railtie" if defined?(Rails::Railtie)

# TODO: Require other necessary files like configuration, engine, etc.
# require_relative "api_keys/configuration"
# require_relative "api_keys/engine"
# require_relative "api_keys/railtie" if defined?(Rails::Railtie)
