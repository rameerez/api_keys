# frozen_string_literal: true

require "test_helper"
require "rails/generators/test_case"
require "generators/api_keys/add_refusal_stats_generator"
require "generators/api_keys/install_generator"

module ApiKeys
  module Generators
    class AddRefusalStatsGeneratorTest < Rails::Generators::TestCase
      tests ApiKeys::Generators::AddRefusalStatsGenerator
      destination File.expand_path("../../tmp/add_refusal_stats_generator", __dir__)
      setup :prepare_destination

      test "generates an idempotent refusal stats migration" do
        run_generator

        assert_migration "db/migrate/add_refusal_stats_to_api_keys.rb" do |migration|
          assert_includes migration, "class AddRefusalStatsToApiKeys < ActiveRecord::Migration["
          assert_includes migration, "add_column :api_keys, :last_refused_at, :datetime"
          assert_includes migration, "add_column :api_keys, :refusals_count, :bigint, default: 0, null: false"
          assert_includes migration, "add_column :api_keys, :last_refusal_code, :string, limit: 64"
          assert_includes migration, "unless column_exists?(:api_keys, :last_refused_at)"
          refute_match(/:last_used_at|:requests_count/, migration, "the migration must never touch the usage columns")
          refute_includes migration, "def migration_version"
        end
      end

      test "the generated migration really adds, re-runs and removes the columns" do
        run_generator
        load migration_file_name("db/migrate/add_refusal_stats_to_api_keys.rb")
        migration = ::AddRefusalStatsToApiKeys.new
        columns = ApiKeys::ApiKey::REFUSAL_STATS_COLUMNS

        RefusalStatsSchema.without_columns do
          ActiveRecord::Migration.suppress_messages do
            migration.migrate(:up)
            migration.migrate(:up) # idempotent: a second run is a no-op
          end
          ApiKeys::ApiKey.reset_column_information
          assert ApiKeys::ApiKey.refusal_stats_columns?
          counter = ApiKeys::ApiKey.columns_hash["refusals_count"]
          assert_equal 0, counter.default.to_i
          refute counter.null

          ActiveRecord::Migration.suppress_messages { migration.migrate(:down) }
          ApiKeys::ApiKey.reset_column_information
          assert_empty columns & ApiKeys::ApiKey.column_names
        end

        assert ApiKeys::ApiKey.refusal_stats_columns?, "the shared test schema is restored"
      ensure
        Object.send(:remove_const, :AddRefusalStatsToApiKeys) if Object.const_defined?(:AddRefusalStatsToApiKeys)
      end
    end

    class InstallGeneratorRefusalStatsTest < Rails::Generators::TestCase
      tests ApiKeys::Generators::InstallGenerator
      destination File.expand_path("../../tmp/install_generator_refusal_stats", __dir__)
      setup :prepare_destination

      test "new installs get the refusal stats columns from the start" do
        run_generator

        assert_migration "db/migrate/create_api_keys_table.rb" do |migration|
          assert_includes migration, "t.datetime :last_refused_at"
          assert_includes migration, "t.bigint   :refusals_count, default: 0, null: false"
          assert_includes migration, "t.string   :last_refusal_code, limit: 64"
        end
      end
    end
  end
end
