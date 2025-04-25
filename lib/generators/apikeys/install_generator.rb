# frozen_string_literal: true

require "rails/generators/base"
require "rails/generators/active_record"

module Apikeys
  module Generators
    # Rails generator for installing the Apikeys gem.
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
        template "initializer.rb.erb", "config/initializers/apikeys.rb"
      end

      # Displays helpful information to the user after installation.
      def display_post_install_message
        say "\n🎉 Apikeys gem successfully installed!", :green
        say "\nNext steps:"
        say "  1. Review the generated migration file in `db/migrate/`."
        say "  2. Run `rails db:migrate` to create the `api_keys` table."
        say "     ☢️  Run migrations before starting your application!", :yellow
        say "  3. Add `has_api_keys` to your owner model(s) (e.g., `app/models/user.rb`), optionally with a block for configuration:"
        say "       # Example for app/models/user.rb"
        say "       class User < ApplicationRecord"
        say "         has_api_keys do"
        say "           # Optional settings:"
        say "           # max_keys 10"
        say "           # require_name true"
        say "           # default_scopes %w[read]"
        say "         end"
        say "         # ..."
        say "       end"
        say "  4. Configure the gem further in `config/initializers/apikeys.rb` if needed."
        say "  5. Protect your API endpoints by including `Apikeys::Controller` in your API base controller"
        say "     (this includes both Authentication and TenantResolution) and adding the before_action:"
        say "       # Example for app/controllers/api/base_controller.rb"
        say "       class Api::BaseController < ActionController::API"
        say "         include Apikeys::Controller"
        say "         before_action :authenticate_api_key! # Enforce authentication"
        say "         # ..."
        say "       end"
        say "\nSee the README and PRD (.cursor/prd.md) for detailed usage and examples.
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
