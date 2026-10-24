# frozen_string_literal: true

require "rails/generators/base"
require "rails/generators/active_record"

module ApiKeys
  module Generators
    # Rails generator for the device authorizations table (api_keys 0.7.0),
    # which ApiKeys::DeviceFlow needs: a client asks for an API key with the
    # OAuth 2.0 Device Authorization Grant (RFC 8628), and a person approves
    # or denies it in the app. New and existing installations run it alike.
    class AddDeviceAuthorizationsGenerator < Rails::Generators::Base
      include ActiveRecord::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      # Implement the required interface for Rails::Generators::Migration.
      def self.next_migration_number(dirname)
        next_migration_number = current_migration_number(dirname) + 1
        ActiveRecord::Migration.next_migration_number(next_migration_number)
      end

      # Creates the migration file using the template.
      def create_migration_file
        migration_template "create_api_keys_device_authorizations.rb.erb",
                           File.join(db_migrate_path, "create_api_keys_device_authorizations.rb")
      end

      # Displays helpful information to the user after installation.
      def display_post_install_message
        say "\n📟 api_keys device authorizations migration created!", :green
        say "\nNext steps:"
        say "  1. Run `rails db:migrate` to create the api_keys_device_authorizations table."
        say "\n  2. Include ApiKeys::DeviceFlow in an API controller, define"
        say "     device_verification_uri(user_code = nil), and route its create and token actions."
        say "\n  3. Build the page where a person approves: find the request with"
        say "     ApiKeys::DeviceAuthorization.find_undecided_by_user_code(code), then call"
        say "     approve!(owner, by: current_user) or deny!(by: current_user)."
        say "\n  4. Rate-limit the code look-ups on that page (RFC 8628 §5.1), and run"
        say "     ApiKeys::DeviceAuthorization.prune! once a day."
        say "\nSee the api_keys README for detailed usage and examples.", :cyan
      end

      private

      def migration_version
        "[#{ActiveRecord::VERSION::STRING.to_f}]"
      end
    end
  end
end
