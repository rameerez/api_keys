# frozen_string_literal: true

require "test_helper"
require "rails/generators/test_case"
require "generators/api_keys/add_key_types_generator"

module ApiKeys
  module Generators
    # test/databases/check.rb runs this migration as db:migrate does on
    # PostgreSQL, MySQL and SQLite, with strong_migrations. Here: what the
    # generator writes, and a run on the suite's SQLite database.
    class AddKeyTypesGeneratorTest < Rails::Generators::TestCase
      tests ApiKeys::Generators::AddKeyTypesGenerator
      destination File.expand_path("../../tmp/add_key_types_generator", __dir__)
      setup :prepare_destination

      MIGRATION = "db/migrate/add_key_types_to_api_keys.rb"
      COLUMNS = { key_type: [:string, {}], environment: [:string, {}] }.freeze
      INDEXES = [%w[key_type], %w[environment], %w[owner_type owner_id key_type environment]].freeze

      def teardown
        Object.send(:remove_const, :AddKeyTypesToApiKeys) if Object.const_defined?(:AddKeyTypesToApiKeys)
        super
      end

      def generated_migration
        run_generator
        load migration_file_name(MIGRATION)
        ::AddKeyTypesToApiKeys.new
      end

      def index_columns
        ApiKeys::ApiKey.connection.indexes(:api_keys).map(&:columns)
      end

      test "generates an idempotent migration that strong_migrations accepts on PostgreSQL" do
        run_generator

        assert_migration MIGRATION do |migration|
          assert_includes migration, "class AddKeyTypesToApiKeys < ActiveRecord::Migration["
          assert_includes migration, "disable_ddl_transaction!"
          assert_includes migration, "add_column :api_keys, :key_type, :string unless column_exists?(:api_keys, :key_type)"
          assert_includes migration, "add_index :api_keys, column, **index_algorithm unless index_exists?(:api_keys, column)"
          assert_includes migration, "remove_invalid_index(OWNER_TYPE_ENV_COLUMNS)"
          assert_includes migration, 'OWNER_TYPE_ENV_INDEX = "index_api_keys_owner_type_env"'
          assert_includes migration, "with_safety_assured do"
          assert_includes migration, "{ algorithm: :concurrently }"
          refute_includes migration, "def change"
          refute_includes migration, "def migration_version"
        end
      end

      test "the indexes are built concurrently on PostgreSQL and PostGIS, and as usual elsewhere" do
        migration = generated_migration
        { "PostgreSQL" => { algorithm: :concurrently }, "PostGIS" => { algorithm: :concurrently },
          "Mysql2" => {}, "Trilogy" => {}, "SQLite" => {} }.each do |adapter, options|
          migration.stubs(:connection).returns(stub(adapter_name: adapter))

          assert_equal options, migration.send(:index_algorithm), adapter
        end
      end

      test "the four-column index uses strong_migrations' safety_assured only when the app has it" do
        migration = generated_migration
        ran = []

        migration.send(:with_safety_assured) { ran << :without }
        migration.define_singleton_method(:safety_assured) do |&block|
          ran << :assured
          block.call
        end
        migration.send(:with_safety_assured) { ran << :with }

        assert_equal %i[without assured with], ran
      end

      test "the generated migration adds, re-runs and removes the columns and the indexes" do
        migration = generated_migration
        connection = ApiKeys::ApiKey.connection

        OptionalColumnsSchema.without(COLUMNS) do
          # SQLite keeps the four-column index, cut down to the owner columns,
          # when the columns go. An install from before key types has none.
          connection.remove_index(:api_keys, name: "index_api_keys_owner_type_env")
          assert_empty INDEXES & index_columns, "precondition: not migrated"
          ActiveRecord::Migration.suppress_messages do
            migration.migrate(:up)
            migration.migrate(:up) # idempotent: a second run is a no-op
          end
          ApiKeys::ApiKey.reset_column_information
          assert_empty %w[key_type environment] - ApiKeys::ApiKey.column_names
          INDEXES.each { |columns| assert_equal 1, index_columns.count(columns), columns.join(", ") }

          # A run that stopped before the last index builds it on the next run.
          connection.remove_index(:api_keys, name: "index_api_keys_owner_type_env")
          ActiveRecord::Migration.suppress_messages { migration.migrate(:up) }
          assert_includes index_columns, INDEXES.last

          ActiveRecord::Migration.suppress_messages { migration.migrate(:down) }
          ApiKeys::ApiKey.reset_column_information
          assert_empty %w[key_type environment] & ApiKeys::ApiKey.column_names
          assert_empty INDEXES & index_columns, "no index is left, not even a shortened one"

          # Leaves the shared test schema with its indexes.
          ActiveRecord::Migration.suppress_messages { migration.migrate(:up) }
        end

        INDEXES.each { |columns| assert_includes index_columns, columns }
      end
    end
  end
end
