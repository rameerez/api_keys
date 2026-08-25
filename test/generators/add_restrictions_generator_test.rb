# frozen_string_literal: true

require "test_helper"
require "rails/generators/test_case"
require "generators/api_keys/add_restrictions_generator"

module ApiKeys
  module Generators
    class AddRestrictionsGeneratorTest < Rails::Generators::TestCase
      tests ApiKeys::Generators::AddRestrictionsGenerator
      destination File.expand_path("../../tmp/add_restrictions_generator", __dir__)
      setup :prepare_destination

      test "generates a restrictions column migration that is unrestricted by default" do
        run_generator

        assert_migration "db/migrate/add_restrictions_to_api_keys.rb" do |migration|
          assert_includes migration, "class AddRestrictionsToApiKeys < ActiveRecord::Migration["
          assert_includes migration, "add_column :api_keys, :restrictions, json_column_type, default: {}, null: false"
          assert_includes migration, "def json_column_type"
          assert_includes migration, ":jsonb"
          assert_includes migration, "rescue ActiveRecord::ConnectionNotEstablished"
          refute_includes migration, "def migration_version"
        end
      end
    end
  end
end
