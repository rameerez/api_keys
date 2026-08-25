# frozen_string_literal: true

require "rails/generators/base"
require "rails/generators/active_record"

module ApiKeys
  module Generators
    # Rails generator for adding the `restrictions` column to the api_keys table.
    # This generator is for existing installations that want to lock keys to
    # specific web origins or IP addresses. New installs get the column from the
    # install generator, so they never need to run this.
    class AddRestrictionsGenerator < Rails::Generators::Base
      include ActiveRecord::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      # Implement the required interface for Rails::Generators::Migration.
      def self.next_migration_number(dirname)
        next_migration_number = current_migration_number(dirname) + 1
        ActiveRecord::Migration.next_migration_number(next_migration_number)
      end

      # Creates the migration file using the template.
      def create_migration_file
        migration_template "add_restrictions_to_api_keys.rb.erb",
                           File.join(db_migrate_path, "add_restrictions_to_api_keys.rb")
      end

      # Displays helpful information to the user after installation.
      def display_post_install_message
        say "\n🌐 Request restrictions migration created!", :green
        say "\nNext steps:"
        say "  1. Run `rails db:migrate` to add the restrictions column."
        say "\n  2. Lock a key to the places it may be used from:"
        say "       user.create_api_key!(name: 'Widget key', allowed_origins: 'example.com, *.example.com')"
        say "       key.allowed_ips = '203.0.113.7, 10.0.0.0/8'"
        say "\n     Keys without restrictions keep working from anywhere; presence is the toggle."
        say "\n  3. Optionally cap which restriction kinds each key type may carry:"
        say "       config.key_types = {"
        say "         publishable: { prefix: 'pk', permissions: %w[read], revocable: false,"
        say "                        public: true, restrictions: [:origins] },"
        say "         secret:      { prefix: 'sk', permissions: :all, restrictions: [:ips] }"
        say "       }"
        say "\n  4. Behind a CDN or proxy, make sure the client IP is truthful:"
        say "       config.action_dispatch.trusted_proxies = ..."
        say "       # or: config.client_ip_resolver = ->(request) { request.headers['CF-Connecting-IP'] }"
        say "\nSee the api_keys README for detailed usage and examples.", :cyan
      end

      private

      def migration_version
        "[#{ActiveRecord::VERSION::STRING.to_f}]"
      end
    end
  end
end
