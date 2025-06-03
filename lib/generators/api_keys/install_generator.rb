# frozen_string_literal: true

require "rails/generators/base"
require "rails/generators/active_record"

module ApiKeys
  module Generators
    # Rails generator for installing the ApiKeys gem.
    # Creates the necessary migration and initializer file.
    class InstallGenerator < Rails::Generators::Base
      include ActiveRecord::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      # Implement the required interface for Rails::Generators::Migration.
      # Borrowed from ActiveRecord::Generators::Base
      # https://github.com/rails/rails/blob/main/activerecord/lib/rails/generators/active_record/base.rb#L31
      def self.next_migration_number(dirname)
        next_migration_number = current_migration_number(dirname) + 1
        ActiveRecord::Migration.next_migration_number(next_migration_number)
      end

      # Creates the migration file using the template.
      def create_migration_file
        migration_template "create_api_keys_table.rb.erb",
                           File.join(db_migrate_path, "create_api_keys_table.rb")
      end

      # Creates the initializer file using the template.
      def create_initializer
        template "initializer.rb", "config/initializers/api_keys.rb"
      end

      # Displays helpful information to the user after installation.
      def display_post_install_message
        say "\n🎉 api_keys gem successfully installed!", :green
        say "\nNext steps:"
        say "  1. Run `rails db:migrate` to create the `api_keys` table."
        say "     ☢️  Run migrations before starting your application!", :yellow
        say "\n  2. Add `has_api_keys` to any models that need to have API keys, with an optional block for configuration:"
        say "       # Example for app/models/user.rb"
        say "       class User < ApplicationRecord"
        say "         has_api_keys do"
        say "           # Optional settings:"
        say "           # max_keys 10"
        say "         end"
        say "         # ..."
        say "       end"
        say "\n  3. IMPORTANT: If API keys belong to a model other than User (e.g., Organization),"
        say "     configure the owner context in `config/initializers/api_keys.rb`:", :yellow
        say "       # For Organization-owned API keys:"
        say "       config.current_owner_method = :current_organization"
        say "       config.authenticate_owner_method = :authenticate_organization!"
        say "\n     The dashboard requires these methods to exist in your ApplicationController"
        say "     or wherever you mount the engine. They should:"
        say "     - `current_owner_method`: return the logged-in owner (e.g., current_organization)"
        say "     - `authenticate_owner_method`: ensure the owner is authenticated"
        say "\n  4. Mount the API keys dashboard in your `routes.rb` to provide a self-serve interface:"
        say "       # In config/routes.rb"
        say "       mount ApiKeys::Engine => '/settings/api-keys'"
        say "\n  5. In your app's API controllers, verify API keys by including `ApiKeys::Controller`:"
        say "       # Example for app/controllers/api/base_controller.rb"
        say "       class Api::BaseController < ActionController::API"
        say "         include ApiKeys::Controller"
        say "         before_action :authenticate_api_key! # Enforce authentication"
        say "         # ..."
        say "       end"
        say "\nSee the api_keys README for detailed usage and examples.
", :cyan
        say "Happy coding! 🚀", :green
      end

      private

      def migration_version
        "[#{ActiveRecord::VERSION::STRING.to_f}]"
      end

    end
  end
end
