# frozen_string_literal: true

require "rails/generators/base"
require "rails/generators/active_record"

module ApiKeys
  module Generators
    # Rails generator for adding the refused-traffic statistics columns
    # (`last_refused_at`, `refusals_count`, `last_refusal_code`) to the api_keys
    # table. This generator is for existing installations; new installs get the
    # columns from the install generator, so they never need to run this.
    class AddRefusalStatsGenerator < Rails::Generators::Base
      include ActiveRecord::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      # Implement the required interface for Rails::Generators::Migration.
      def self.next_migration_number(dirname)
        next_migration_number = current_migration_number(dirname) + 1
        ActiveRecord::Migration.next_migration_number(next_migration_number)
      end

      # Creates the migration file using the template.
      def create_migration_file
        migration_template "add_refusal_stats_to_api_keys.rb.erb",
                           File.join(db_migrate_path, "add_refusal_stats_to_api_keys.rb")
      end

      # Displays helpful information to the user after installation.
      def display_post_install_message
        say "\n🚦 Refused-traffic statistics migration created!", :green
        say "\nNext steps:"
        say "  1. Run `rails db:migrate` to add last_refused_at, refusals_count and last_refusal_code."
        say "\n  2. That's it. Requests that present a key's real token and are refused"
        say "     (origin/IP restrictions, environment, missing scope, revoked, expired...)"
        say "     are now stamped on the key, through the same background stats job as"
        say "     last_used_at, and the dashboard shows them on the key's page."
        say "\n     A refusal never moves last_used_at or requests_count."
        say "     refusals_count, like requests_count, is only kept with `config.track_requests_count = true`."
        say "\nSee the api_keys README for detailed usage and examples.", :cyan
      end

      private

      def migration_version
        "[#{ActiveRecord::VERSION::STRING.to_f}]"
      end
    end
  end
end
