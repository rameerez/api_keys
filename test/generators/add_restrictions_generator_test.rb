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
      # Generator tests do not reset the configuration; another test may have
      # left key types on.
      setup { ApiKeys.reset_configuration! }

      test "generates a restrictions column migration that is unrestricted by default" do
        run_generator

        assert_migration "db/migrate/add_restrictions_to_api_keys.rb" do |migration|
          assert_includes migration, "class AddRestrictionsToApiKeys < ActiveRecord::Migration["
          assert_includes migration, "disable_ddl_transaction!"
          assert_includes migration, "add_column :api_keys, :restrictions, json_column_type, default: restrictions_default, null: false"
          assert_includes migration, "unless column_exists?(:api_keys, :restrictions)"
          assert_includes migration, "unless restrictions_constraint_exists?"
          assert_includes migration, "postgresql? ? { validate: false } : {}"
          assert_includes migration, "validate_check_constraint :api_keys, name: CONSTRAINT_NAME if postgresql?"
          assert_includes migration, '-> { "(JSON_OBJECT())" }'
          assert_includes migration, "def json_column_type"
          assert_includes migration, ":jsonb"
          assert_includes migration, "rescue ActiveRecord::ConnectionNotEstablished"
          assert_includes migration, "jsonb_typeof(restrictions) = 'object'"
          assert_includes migration, "json_type(restrictions) = 'object'"
          assert_includes migration, "JSON_TYPE(restrictions) = 'OBJECT'"
          refute_includes migration, "def migration_version"
        end
      end

      def generated_migration
        run_generator
        load migration_file_name("db/migrate/add_restrictions_to_api_keys.rb")
        ::AddRestrictionsToApiKeys.new
      end

      def teardown
        Object.send(:remove_const, :AddRestrictionsToApiKeys) if Object.const_defined?(:AddRestrictionsToApiKeys)
        super
      end

      # test/databases/check.rb runs this migration as db:migrate does on
      # PostgreSQL, MySQL and SQLite, with strong_migrations.
      test "each database gets its column type and default, and PostgreSQL validates apart" do
        migration = generated_migration
        {
          "PostgreSQL" => [:jsonb, {}, true], "PostGIS" => [:jsonb, {}, true],
          "Mysql2" => [:json, "(JSON_OBJECT())", false], "Trilogy" => [:json, "(JSON_OBJECT())", false],
          "SQLite" => [:json, {}, false]
        }.each do |adapter, (type, default, postgresql)|
          migration.stubs(:connection).returns(stub(adapter_name: adapter))
          resolved = migration.send(:restrictions_default)

          assert_equal type, migration.send(:json_column_type), adapter
          assert_equal default, resolved.respond_to?(:call) ? resolved.call : resolved, adapter
          assert_equal postgresql, migration.send(:postgresql?), adapter
        end
      end

      test "the generated migration adds, re-runs and removes the column and its constraint" do
        migration = generated_migration
        connection = ApiKeys::ApiKey.connection
        constraint = -> { connection.check_constraints(:api_keys).find { |c| c.name == "api_keys_restrictions_is_object" } }

        OptionalColumnsSchema.without(restrictions: [:text, { default: "{}", null: false }]) do
          # A key from before restrictions existed: a plain row.
          now = Time.current
          ApiKeys::ApiKey.insert_all!([{ prefix: "ak_old_", token_digest: "old-digest", digest_algorithm: "sha256",
                                         last4: "old4", created_at: now, updated_at: now }])
          old_key = ApiKeys::ApiKey.find_by!(token_digest: "old-digest")
          ActiveRecord::Migration.suppress_messages do
            migration.migrate(:up)
            migration.migrate(:up) # idempotent: a second run is a no-op
          end
          ApiKeys::ApiKey.reset_column_information

          assert ApiKeys::ApiKey.restrictions_column?
          assert constraint.call, "the object constraint exists"
          raw = connection.select_value("SELECT restrictions FROM api_keys WHERE id = #{Integer(old_key.id)}")
          assert_equal({}, JSON.parse(raw), "an existing key is unrestricted")
          assert_raises(ActiveRecord::StatementInvalid) do
            connection.execute("UPDATE api_keys SET restrictions = '[]' WHERE id = #{Integer(old_key.id)}")
          end

          ActiveRecord::Migration.suppress_messages { migration.migrate(:down) }
          ApiKeys::ApiKey.reset_column_information
          refute ApiKeys::ApiKey.restrictions_column?
          assert_nil constraint.call
        end

        assert ApiKeys::ApiKey.restrictions_column?, "the shared test schema is restored"
      ensure
        ApiKeys::ApiKey.where(token_digest: "old-digest").delete_all
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
