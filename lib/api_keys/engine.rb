# frozen_string_literal: true

require "rails/engine"
require_relative "models/concerns/has_api_keys" # Ensure concern is loaded

module ApiKeys
  # Rails engine for ApiKeys
  class Engine < ::Rails::Engine
    isolate_namespace ApiKeys

    # Allows configuring the parent controller for the engine's controllers
    # Defaults to ::ApplicationController, assuming a standard Rails app structure.
    config.parent_controller = '::ApplicationController'

    # Ensure our models load first
    config.autoload_paths << File.expand_path("../models", __dir__)
    config.autoload_paths << File.expand_path("../models/concerns", __dir__)

    # Set up autoloading paths
    initializer "api_keys.autoload", before: :set_autoload_paths do |app|
      app.config.autoload_paths << root.join("lib")
      app.config.autoload_paths << root.join("lib/api_keys/models")
      app.config.autoload_paths << root.join("lib/api_keys/models/concerns")
    end

    # Add has_api_keys method to ActiveRecord::Base
    initializer "api_keys.active_record" do
      ActiveSupport.on_load(:active_record) do
        # Extend all AR models with the ClassMethods module from HasApiKeys
        # This makes the `has_api_keys` method available directly on models like User.
        extend ApiKeys::Models::Concerns::HasApiKeys::ClassMethods
      end
    end


    # Load JSON attribute types after ActiveRecord initialization
    # and database connection is established.
    initializer "api_keys.model_attributes" do
      ActiveSupport.on_load(:active_record) do
        ApiKeys::ApiKey.class_eval do
          # Define JSON attributes for ApiKey model
          # Ensure the ApiKey model class is loaded before reopening
          # Use require_dependency for development/test, rely on autoloading in production
          # Or simply let Zeitwerk handle loading if structure is correct.
          require_dependency "api_keys/models/api_key" if defined?(Rails) && !Rails.env.production?

          # == JSON Attribute Casting ==
          # Make the gem work in any database (postgres, sqlite3, mysql...)
          # Configure the right json-like attributes for the different databases
          # according to the migration (jsonb = postgres; text = elsewhere)
          # So that the JSON attributes work in any database
          # and the gem works everywhere, transparent to end users
          json_col_type = ApiKeys::ApiKey.connection.adapter_name.downcase.include?('postg') ? :jsonb : :json
          ApiKeys::ApiKey.attribute :scopes, json_col_type, default: []
          ApiKeys::ApiKey.attribute :metadata, json_col_type, default: {}

        end
      end
    end


    # Add other initializers here if needed (e.g., for configuration loading,
    # middleware injection, asset precompilation, etc.)

    # Example: Load configuration defaults
    # initializer "api_keys.configuration" do
    #   require_relative "../config"
    #   # Potentially load default config values here
    # end

    # Example: Add middleware if needed
    # initializer "api_keys.middleware" do |app|
    #   # app.middleware.use ApiKeys::Middleware::SomeMiddleware
    # end
  end
end
