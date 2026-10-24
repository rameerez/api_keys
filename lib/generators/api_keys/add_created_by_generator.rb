# frozen_string_literal: true

require "rails/generators/base"
require "rails/generators/active_record"

module ApiKeys
  module Generators
    # Rails generator for the column api_keys 0.7.0 adds to the api_keys
    # table: `created_by`, the person behind a key.
    #
    # This generator is for existing installations; new installs get the
    # columns from the install generator, so they never need to run this.
    class AddCreatedByGenerator < Rails::Generators::Base
      include ActiveRecord::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      # Implement the required interface for Rails::Generators::Migration.
      def self.next_migration_number(dirname)
        next_migration_number = current_migration_number(dirname) + 1
        ActiveRecord::Migration.next_migration_number(next_migration_number)
      end

      # Creates the migration file using the template.
      def create_migration_file
        migration_template "add_created_by_to_api_keys.rb.erb",
                           File.join(db_migrate_path, "add_created_by_to_api_keys.rb")
      end

      # Displays helpful information to the user after installation.
      def display_post_install_message
        say "\n🧑 api_keys created_by migration created!", :green
        say "\nNext steps:"
        say "  1. Run `rails db:migrate` to add created_by_type and created_by_id to api_keys."
        say "\n  2. Name the person when you create a key:"
        say "       current_organization.create_api_key!(name: \"CI\", created_by: current_user)"
        say "\n  3. Optional: refuse a key once its person no longer stands behind it:"
        say "       config.trusted_key_check = ->(api_key) { api_key.owner.managed_by?(api_key.created_by) }"
        say "     Keys made before the migration have no created_by: decide what the check does with them."
        say "\nSee the api_keys README for detailed usage and examples.", :cyan
      end

      private

      def migration_version
        "[#{ActiveRecord::VERSION::STRING.to_f}]"
      end
    end
  end
end
