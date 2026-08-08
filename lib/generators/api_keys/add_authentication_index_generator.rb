# frozen_string_literal: true

require "rails/generators/base"
require "rails/generators/active_record"

module ApiKeys
  module Generators
    # Adds the bounded bcrypt authentication lookup index to existing installs.
    class AddAuthenticationIndexGenerator < Rails::Generators::Base
      include ActiveRecord::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      def self.next_migration_number(dirname)
        number = current_migration_number(dirname) + 1
        ActiveRecord::Migration.next_migration_number(number)
      end

      def create_migration_file
        migration_template "add_authentication_index_to_api_keys.rb.erb",
                           File.join(db_migrate_path, "add_authentication_index_to_api_keys.rb")
      end

      def display_post_install_message
        say "\n🔐 API key authentication index migration created.", :green
        say "Run `rails db:migrate` before deploying bcrypt authentication changes."
      end

      private

      def migration_version
        "[#{ActiveRecord::VERSION::MAJOR}.#{ActiveRecord::VERSION::MINOR}]"
      end
    end
  end
end
