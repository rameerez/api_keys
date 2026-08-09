# frozen_string_literal: true

require "test_helper"
require "rails/generators/test_case"
require "generators/api_keys/add_authentication_index_generator"

module ApiKeys
  module Generators
    class AddAuthenticationIndexGeneratorTest < Rails::Generators::TestCase
      tests ApiKeys::Generators::AddAuthenticationIndexGenerator
      destination File.expand_path("../../tmp/add_authentication_index_generator", __dir__)
      setup :prepare_destination

      test "generates an idempotent bounded lookup index migration" do
        run_generator

        assert_migration "db/migrate/add_authentication_index_to_api_keys.rb" do |migration|
          assert_includes migration, 'INDEX_NAME = "index_api_keys_authentication_lookup"'
          assert_includes migration, "COLUMNS = %i[prefix last4 digest_algorithm].freeze"
          assert_includes migration, "index_exists?(:api_keys, COLUMNS, name: INDEX_NAME)"
          assert_includes migration, "algorithm] = :concurrently"
          assert_includes migration, "disable_ddl_transaction!"
          refute_includes migration, "def migration_version"
        end
      end
    end
  end
end
