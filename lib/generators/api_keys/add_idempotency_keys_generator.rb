# frozen_string_literal: true

require "rails/generators/base"
require "rails/generators/active_record"

module ApiKeys
  module Generators
    # Rails generator for the Idempotency-Keys table (api_keys 0.7.0), which
    # ApiKeys::Idempotency needs: each write under an Idempotency-Key runs
    # once per API key, and a retry answers the record as it is now. New and
    # existing installations run it alike.
    class AddIdempotencyKeysGenerator < Rails::Generators::Base
      include ActiveRecord::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      # Implement the required interface for Rails::Generators::Migration.
      def self.next_migration_number(dirname)
        next_migration_number = current_migration_number(dirname) + 1
        ActiveRecord::Migration.next_migration_number(next_migration_number)
      end

      # Creates the migration file using the template.
      def create_migration_file
        migration_template "create_api_keys_idempotency_keys.rb.erb",
                           File.join(db_migrate_path, "create_api_keys_idempotency_keys.rb")
      end

      # Displays helpful information to the user after installation.
      def display_post_install_message
        say "\n🔁 api_keys Idempotency-Keys migration created!", :green
        say "\nNext steps:"
        say "  1. Run `rails db:migrate` to create the api_keys_idempotency_keys table."
        say "\n  2. In your API base controller, after authenticate_api_key!:"
        say "       include ApiKeys::Idempotency"
        say "       around_action :run_once_per_idempotency_key"
        say "\n  3. Answer every write with render_resource(record, status: ...), and define"
        say "     resource_json(record, **options) to render a record and"
        say "     idempotent_replay_allowed?(record) to say whether current_api_key may read it."
        say "     Keep the around_action outside any transaction your app opens."
        say "\n  4. Run ApiKeys::IdempotencyKey.prune! once a day."
        say "\nSee the api_keys README for detailed usage and examples.", :cyan
      end

      private

      def migration_version
        "[#{ActiveRecord::VERSION::STRING.to_f}]"
      end
    end
  end
end
