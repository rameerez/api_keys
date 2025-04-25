# frozen_string_literal: true

require "rails/engine"
require_relative "models/concerns/has_api_keys" # Ensure concern is loaded

module Apikeys
  # Rails engine for Apikeys
  class Engine < ::Rails::Engine
    isolate_namespace Apikeys

    # Ensure our models load first
    config.autoload_paths << File.expand_path("../models", __dir__)
    config.autoload_paths << File.expand_path("../models/concerns", __dir__)

    # Set up autoloading paths
    initializer "apikeys.autoload", before: :set_autoload_paths do |app|
      app.config.autoload_paths << root.join("lib")
      app.config.autoload_paths << root.join("lib/apikeys/models")
      app.config.autoload_paths << root.join("lib/apikeys/models/concerns")
    end


    # Add has_api_keys method to ActiveRecord::Base
    initializer "apikeys.active_record" do
      ActiveSupport.on_load(:active_record) do
        # Extend all AR models with the ClassMethods module from HasApiKeys
        # This makes the `has_api_keys` method available directly on models like User.
        extend Apikeys::Models::Concerns::HasApiKeys::ClassMethods
      end
    end

    # Add other initializers here if needed (e.g., for configuration loading,
    # middleware injection, asset precompilation, etc.)

    # Example: Load configuration defaults
    # initializer "apikeys.configuration" do
    #   require_relative "../config"
    #   # Potentially load default config values here
    # end

    # Example: Add middleware if needed
    # initializer "apikeys.middleware" do |app|
    #   # app.middleware.use Apikeys::Middleware::SomeMiddleware
    # end
  end
end
