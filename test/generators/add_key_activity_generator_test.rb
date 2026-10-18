# frozen_string_literal: true

require "test_helper"
require "rails/generators/test_case"
require "generators/api_keys/add_key_activity_generator"
require "generators/api_keys/install_generator"

module ApiKeys
  module Generators
    class AddKeyActivityGeneratorTest < Rails::Generators::TestCase
      tests ApiKeys::Generators::AddKeyActivityGenerator
      destination File.expand_path("../../tmp/add_key_activity_generator", __dir__)
      setup :prepare_destination

      ACTIVITY_COLUMNS = (ApiKeys::ApiKey::REFUSAL_STATS_COLUMNS + [ApiKeys::ApiKey::TOKEN_SHOWN_AT_COLUMN]).freeze

      test "generates one idempotent migration with every 0.6.0 column" do
        run_generator

        assert_migration "db/migrate/add_key_activity_to_api_keys.rb" do |migration|
          assert_includes migration, "class AddKeyActivityToApiKeys < ActiveRecord::Migration["
          assert_includes migration, "add_column :api_keys, :last_refused_at, :datetime"
          assert_includes migration, "add_column :api_keys, :refusals_count, :bigint, default: 0, null: false"
          assert_includes migration, "add_column :api_keys, :last_refusal_code, :string, limit: 64"
          assert_includes migration, "add_column :api_keys, :token_shown_at, :datetime"
          ACTIVITY_COLUMNS.each do |column|
            assert_includes migration, "unless column_exists?(:api_keys, :#{column})"
          end
          refute_match(/:last_used_at|:requests_count/, migration, "the migration must never touch the usage columns")
          refute_includes migration, "def migration_version"
        end
      end

      test "the generated migration really adds, re-runs and removes the columns" do
        run_generator
        load migration_file_name("db/migrate/add_key_activity_to_api_keys.rb")
        migration = ::AddKeyActivityToApiKeys.new
        all_columns = RefusalStatsSchema::COLUMNS.merge(TokenShownAtSchema::COLUMNS)

        OptionalColumnsSchema.without(all_columns) do
          refute ApiKeys::ApiKey.token_shown_at_column?, "precondition: not migrated"
          ActiveRecord::Migration.suppress_messages do
            migration.migrate(:up)
            migration.migrate(:up) # idempotent: a second run is a no-op
          end
          ApiKeys::ApiKey.reset_column_information
          assert ApiKeys::ApiKey.refusal_stats_columns?
          assert ApiKeys::ApiKey.token_shown_at_column?
          counter = ApiKeys::ApiKey.columns_hash["refusals_count"]
          assert_equal 0, counter.default.to_i
          refute counter.null
          assert ApiKeys::ApiKey.columns_hash["token_shown_at"].null, "existing keys keep NULL"

          ActiveRecord::Migration.suppress_messages { migration.migrate(:down) }
          ApiKeys::ApiKey.reset_column_information
          assert_empty ACTIVITY_COLUMNS & ApiKeys::ApiKey.column_names
        end

        assert ApiKeys::ApiKey.refusal_stats_columns?, "the shared test schema is restored"
        assert ApiKeys::ApiKey.token_shown_at_column?, "the shared test schema is restored"
      ensure
        Object.send(:remove_const, :AddKeyActivityToApiKeys) if Object.const_defined?(:AddKeyActivityToApiKeys)
      end

      test "an install that already has some of the columns gains only the missing ones" do
        run_generator
        load migration_file_name("db/migrate/add_key_activity_to_api_keys.rb")
        migration = ::AddKeyActivityToApiKeys.new

        # A 0.6.0 pre-release install that ran the refusal-stats migration
        # before token_shown_at existed.
        TokenShownAtSchema.without_column do
          assert ApiKeys::ApiKey.refusal_stats_columns?
          ActiveRecord::Migration.suppress_messages { migration.migrate(:up) }
          ApiKeys::ApiKey.reset_column_information
          assert ApiKeys::ApiKey.token_shown_at_column?
        end
      ensure
        Object.send(:remove_const, :AddKeyActivityToApiKeys) if Object.const_defined?(:AddKeyActivityToApiKeys)
      end
    end

    class InstallGeneratorKeyActivityTest < Rails::Generators::TestCase
      tests ApiKeys::Generators::InstallGenerator
      destination File.expand_path("../../tmp/install_generator_key_activity", __dir__)
      setup :prepare_destination

      test "new installs get every 0.6.0 column from the start" do
        run_generator

        assert_migration "db/migrate/create_api_keys_table.rb" do |migration|
          assert_includes migration, "t.datetime :last_refused_at"
          assert_includes migration, "t.bigint   :refusals_count, default: 0, null: false"
          assert_includes migration, "t.string   :last_refusal_code, limit: 64"
          assert_includes migration, "t.datetime :token_shown_at"
        end
      end
    end
  end
end
