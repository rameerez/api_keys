# frozen_string_literal: true

require "test_helper"
require "rails/generators/test_case"
require "generators/api_keys/install_generator"

module ApiKeys
  module Generators
    class InstallGeneratorTest < Rails::Generators::TestCase
      tests ApiKeys::Generators::InstallGenerator
      destination File.expand_path("../../tmp/install_generator", __dir__)
      setup :prepare_destination

      test "generates only the useful polymorphic owner indexes" do
        run_generator

        assert_migration "db/migrate/create_api_keys_table.rb" do |migration|
          assert_includes migration, "t.references :owner, polymorphic: true"
          assert_includes migration, "[:owner_type, :owner_id, :key_type, :environment]"
          refute_match(/^\s*t\.index :owner_id\b/, migration)
          refute_match(/^\s*t\.index :owner_type\b/, migration)
          refute_includes migration, "def migration_version"
        end
      end
    end
  end
end
