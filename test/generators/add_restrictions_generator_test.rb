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
          assert_includes migration, "jsonb_typeof(restrictions) = 'object'"
          assert_includes migration, "json_type(restrictions) = 'object'"
          assert_includes migration, "JSON_TYPE(restrictions) = 'OBJECT'"
          refute_includes migration, "def migration_version"
        end
      end

      test "the SQLite constraint accepts objects and rejects scalar JSON" do
        connection = ActiveRecord::Base.connection
        table = :api_keys_restrictions_constraint_probe
        connection.create_table(table) { |definition| definition.json :restrictions, null: false }
        connection.add_check_constraint(
          table,
          "json_valid(restrictions) AND json_type(restrictions) = 'object'",
          name: "restrictions_is_object"
        )

        connection.execute("INSERT INTO #{connection.quote_table_name(table)} (restrictions) VALUES ('{}')")
        assert_raises(ActiveRecord::StatementInvalid) do
          connection.execute("INSERT INTO #{connection.quote_table_name(table)} (restrictions) VALUES ('[]')")
        end
      ensure
        connection&.drop_table(table, if_exists: true)
      end
    end
  end
end
