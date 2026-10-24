# frozen_string_literal: true

require "test_helper"
require "rails/generators/test_case"
require "generators/api_keys/add_device_authorizations_generator"

module ApiKeys
  module Generators
    class AddDeviceAuthorizationsGeneratorTest < Rails::Generators::TestCase
      tests ApiKeys::Generators::AddDeviceAuthorizationsGenerator
      destination File.expand_path("../../tmp/add_device_authorizations_generator", __dir__)
      setup :prepare_destination
      setup { ApiKeys.reset_configuration! } # other suites configure key types

      FILE = "db/migrate/create_api_keys_device_authorizations.rb"

      test "generates the table with digests only, never the codes" do
        run_generator

        assert_migration FILE do |migration|
          assert_includes migration, "class CreateApiKeysDeviceAuthorizations < ActiveRecord::Migration["
          assert_includes migration, "create_table :api_keys_device_authorizations"
          assert_includes migration, "t.string :device_code_digest, null: false, index: { unique: true }"
          assert_includes migration, "t.string :user_code_digest, null: false, index: { unique: true }"
          assert_includes migration, "foreign_key: { on_delete: :nullify }"
          refute_match(/t\.string :(device|user)_code\b/, migration)
          assert_includes migration, "t.send(json_column_type, :scopes, null: false)"
          refute_match(/:scopes, default:/, migration, "MySQL refuses a literal default on a JSON column")
          refute_includes migration, "def migration_version"
        end
      end

      test "the generated migration really creates and drops the table the model uses" do
        run_generator
        load migration_file_name(FILE)
        connection = ActiveRecord::Base.connection
        connection.drop_table(:api_keys_device_authorizations)
        ApiKeys::DeviceAuthorization.reset_column_information

        ActiveRecord::Migration.suppress_messages { ::CreateApiKeysDeviceAuthorizations.migrate(:up) }
        ApiKeys::DeviceAuthorization.reset_column_information
        columns = ApiKeys::DeviceAuthorization.columns_hash
        assert_equal :json, columns["scopes"].type
        assert_nil columns["scopes"].default
        assert_equal [], ApiKeys::DeviceAuthorization.new.scopes, "the model gives the default"
        assert_equal "pending", columns["state"].default
        assert_equal 5, columns["interval"].default.to_i
        refute columns["expires_at"].null
        assert_equal %w[api_keys], connection.foreign_keys(:api_keys_device_authorizations).map(&:to_table)

        user = ::User.create!(name: "Migrated owner")
        ApiKeys.configuration.default_scopes = %w[read]
        authorization = ApiKeys::DeviceAuthorization.request!(client_id: "Fictional agent", scopes: %w[read])
        authorization.approve!(user, by: user)
        assert authorization.poll!(client_id: "Fictional agent").api_key.persisted?

        ApiKeys::DeviceAuthorization.delete_all
        ActiveRecord::Migration.suppress_messages { ::CreateApiKeysDeviceAuthorizations.migrate(:down) }
        refute connection.table_exists?(:api_keys_device_authorizations)
      ensure
        unless ActiveRecord::Base.connection.table_exists?(:api_keys_device_authorizations)
          ActiveRecord::Migration.suppress_messages { ::CreateApiKeysDeviceAuthorizations.migrate(:up) }
        end
        ApiKeys::DeviceAuthorization.reset_column_information
        ApiKeys.reset_configuration!
        ::User.delete_all
        ApiKeys::ApiKey.delete_all
        Object.send(:remove_const, :CreateApiKeysDeviceAuthorizations) if Object.const_defined?(:CreateApiKeysDeviceAuthorizations)
      end
    end
  end
end
