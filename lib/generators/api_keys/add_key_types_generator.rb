# frozen_string_literal: true

require "rails/generators/base"
require "rails/generators/active_record"

module ApiKeys
  module Generators
    # Rails generator for adding key_type and environment columns to the api_keys table.
    # This generator is for existing installations that want to enable the key types feature.
    class AddKeyTypesGenerator < Rails::Generators::Base
      include ActiveRecord::Generators::Migration

      source_root File.expand_path("templates", __dir__)

      # Implement the required interface for Rails::Generators::Migration.
      def self.next_migration_number(dirname)
        next_migration_number = current_migration_number(dirname) + 1
        ActiveRecord::Migration.next_migration_number(next_migration_number)
      end

      # Creates the migration file using the template.
      def create_migration_file
        migration_template "add_key_types_to_api_keys.rb.erb",
                           File.join(db_migrate_path, "add_key_types_to_api_keys.rb")
      end

      # Displays helpful information to the user after installation.
      def display_post_install_message
        say "\n🔑 Key types migration created!", :green
        say "\nNext steps:"
        say "  1. Run `rails db:migrate` to add the key_type and environment columns."
        say "\n  2. Configure key types in `config/initializers/api_keys.rb`:"
        say "       ApiKeys.configure do |config|"
        say "         config.key_types = {"
        say "           publishable: {"
        say "             prefix: 'pk',"
        say "             permissions: %w[read validate],"
        say "             revocable: false,"
        say "             limit: 1"
        say "           },"
        say "           secret: {"
        say "             prefix: 'sk',"
        say "             permissions: :all"
        say "           }"
        say "         }"
        say ""
        say "         config.environments = {"
        say "           test: { prefix_segment: 'test' },"
        say "           live: { prefix_segment: 'live' }"
        say "         }"
        say ""
        say "         config.current_environment = -> { Rails.env.production? ? :live : :test }"
        say "         config.strict_environment_isolation = true"
        say "       end"
        say "\n  3. Create typed API keys:"
        say "       user.create_api_key!(name: 'My Key', key_type: :publishable)"
        say "       user.create_api_key!(name: 'Admin Key', key_type: :secret)"
        say "\nSee the api_keys README for detailed usage and examples.", :cyan
      end

      private

      def migration_version
        "[#{ActiveRecord::VERSION::STRING.to_f}]"
      end
    end
  end
end
