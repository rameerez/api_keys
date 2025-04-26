# frozen_string_literal: true

require "rails/engine"
require_relative "models/concerns/has_api_keys" # Ensure concern is loaded

module ApiKeys
  # Rails engine for ApiKeys
  class Engine < ::Rails::Engine
    isolate_namespace ApiKeys

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

    # Define JSON attributes after ActiveRecord is loaded and connected.
    initializer "api_keys.model_attributes" do
      ActiveSupport.on_load(:active_record) do
        # Ensure the ApiKey model class is loaded before reopening
        # Use require_dependency for development/test, rely on autoloading in production
        # Or simply let Zeitwerk handle loading if structure is correct.
        require_dependency "api_keys/models/api_key" if defined?(Rails) && !Rails.env.production?

        ApiKeys::ApiKey.class_eval do
          # Define attributes using :json type for proper serialization
          # This runs after the DB connection is likely established.
          attribute :scopes, :json, default: []
          attribute :metadata, :json, default: {}

          # == JSON Attribute Casting ==
          # Make the gem work in any database (postgres, sqlite3, mysql...)
          # Configure the right json-like attributes for the different databases
          # according to the migration (jsonb = postgres; text = elsewhere)
          # So that the JSON attributes work in any database
          # and the gem works everywhere, transparent to end users
          adapter_name = ActiveRecord::Base.connection.adapter_name.downcase rescue "sqlite" # fallback to sqlite

          if adapter_name.include?("postgresql")
            attribute :scopes, :jsonb, default: []
            attribute :metadata, :jsonb, default: {}
          else
            attribute :scopes, :json, default: []
            attribute :metadata, :json, default: {}
          end
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
