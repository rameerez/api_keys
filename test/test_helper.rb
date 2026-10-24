# frozen_string_literal: true

# SimpleCov must be loaded BEFORE any application code
# Configuration is auto-loaded from .simplecov file
require "simplecov"
SimpleCov.start

# Print coverage summary to terminal after tests complete.
SimpleCov.at_exit do
  SimpleCov.result.format!
  puts "\n" + "=" * 60
  puts "COVERAGE SUMMARY"
  puts "=" * 60
  puts "Line Coverage:   #{SimpleCov.result.covered_percent.round(2)}%"
  puts "Branch Coverage: #{SimpleCov.result.coverage_statistics[:branch]&.percent&.round(2) || 'N/A'}%"
  puts "=" * 60
end

ENV["RAILS_ENV"] ||= "test"
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "api_keys"

# Core testing libraries
require "minitest/autorun"
require "minitest/mock"
require "minitest/reporters"
require "mocha/minitest"

# Plain Ruby test doubles that include controller concerns need this Rails class
# macro. Define it once to avoid noisy method-redefinition warnings.
module Kernel
  def helper_method(*); end unless method_defined?(:helper_method)
end

# ActiveSupport test case and helpers
require "active_support/test_case"
require "active_support/testing/time_helpers"

# Database setup
require "active_record"
require "sqlite3"

puts "Setting up test environment..."

# Configure Minitest reporters
Minitest::Reporters.use! [
  Minitest::Reporters::SpecReporter.new,
  # Minitest::Reporters::ProgressReporter.new # Uncomment for progress bar
]

# Establish in-memory SQLite database connection
ActiveRecord::Base.establish_connection(adapter: "sqlite3", database: ":memory:")

# Define schema directly for simplicity in tests
# In a real app, you might load schema.rb from a dummy app
ActiveRecord::Schema.define do
  # Create a basic users table for owner association tests
  create_table :users, force: :cascade do |t|
    t.string :name
    t.timestamps
  end

  # Recreate the api_keys table based on the migration template
  create_table :api_keys, force: :cascade do |t|
    t.string   :prefix,        null: false
    t.string   :token_digest,  null: false
    t.string   :digest_algorithm, null: false
    t.string   :name
    t.references :owner, polymorphic: true, null: true # type: :bigint assumed by default
    t.references :created_by, polymorphic: true, null: true # The person behind the key (0.7.0)
    t.text     :scopes, default: "[]", null: false # Use text for SQLite JSON
    t.text     :metadata, default: "{}", null: false # Use text for SQLite JSON
    t.text     :restrictions, default: "{}", null: false # Origin/IP request restrictions
    t.datetime :expires_at
    t.datetime :last_used_at
    t.bigint   :requests_count, default: 0, null: false
    t.datetime :last_refused_at  # Refused-but-identified traffic (0.6.0)
    t.bigint   :refusals_count, default: 0, null: false
    t.string   :last_refusal_code, limit: 64
    t.datetime :token_shown_at   # Durable one-time token handoff (0.6.0)
    t.datetime :revoked_at
    t.string   :last4, null: false, default: ""
    t.string   :key_type       # New: key type identifier (e.g., "publishable", "secret")
    t.string   :environment    # New: environment identifier (e.g., "test", "live")
    t.timestamps

    t.index :token_digest, unique: true
    t.index :prefix
    t.index [:prefix, :last4, :digest_algorithm], name: "index_api_keys_authentication_lookup"
    t.index [:owner_type, :owner_id]
    t.index :expires_at
    t.index :revoked_at
    t.index :last_used_at
    t.index :key_type
    t.index :environment
    t.index [:owner_type, :owner_id, :key_type, :environment], name: "index_api_keys_owner_type_env"
  end

  # The device flow's requests (0.7.0), as the add_device_authorizations
  # generator creates them.
  create_table :api_keys_device_authorizations, force: :cascade do |t|
    t.string :device_code_digest, null: false, index: { unique: true }
    t.string :user_code_digest, null: false, index: { unique: true }
    t.string :client_id, null: false
    t.string :device_name
    t.string :requested_from
    t.json :scopes, null: false # no default on JSON: MySQL refuses one
    t.string :key_type
    t.string :state, default: "pending", null: false
    t.integer :interval, default: 5, null: false
    t.datetime :expires_at, null: false, index: true
    t.datetime :last_polled_at
    t.references :owner, polymorphic: true, null: true
    t.references :decided_by, polymorphic: true, null: true
    t.datetime :decided_at
    t.references :api_key, null: true, foreign_key: { on_delete: :nullify }
    t.timestamps
  end

  # Writes under an Idempotency-Key (0.7.0), as the add_idempotency_keys
  # generator creates them.
  create_table :api_keys_idempotency_keys, force: :cascade do |t|
    t.references :api_key, null: false, foreign_key: { on_delete: :cascade }, index: false
    t.string :key, null: false
    t.string :request_digest
    t.integer :response_status
    t.references :resource, polymorphic: true, null: true, index: false
    t.timestamps
    t.index :created_at
    t.index [:api_key_id, :key], unique: true
  end
end

# Mirror engine initializer behavior for attribute casting in tests
json_col_type = :json
ApiKeys::ApiKey.attribute :scopes, json_col_type, default: []
ApiKeys::ApiKey.attribute :metadata, json_col_type, default: {}
ApiKeys::ApiKey.attribute :restrictions, json_col_type, default: {}

puts "Database schema loaded."

# Simulates an installation that has not run
# `rails generate api_keys:add_key_activity` yet by really dropping columns
# (not stubbing a predicate), so any code path that touches them without
# checking first fails the test. Restores the schema afterwards.
module OptionalColumnsSchema
  module_function

  def without(columns)
    connection = ApiKeys::ApiKey.connection
    columns.each_key do |column|
      connection.remove_column(:api_keys, column) if connection.column_exists?(:api_keys, column)
    end
    ApiKeys::ApiKey.reset_column_information
    yield
  ensure
    restore!(columns)
  end

  def restore!(columns)
    connection = ApiKeys::ApiKey.connection
    columns.each do |column, (type, options)|
      connection.add_column(:api_keys, column, type, **options) unless connection.column_exists?(:api_keys, column)
    end
    ApiKeys::ApiKey.reset_column_information
  end
end

# The refused-traffic statistics columns.
module RefusalStatsSchema
  COLUMNS = {
    last_refused_at: [:datetime, {}],
    refusals_count: [:bigint, { default: 0, null: false }],
    last_refusal_code: [:string, { limit: 64 }]
  }.freeze

  module_function

  def without_columns(&block)
    OptionalColumnsSchema.without(COLUMNS, &block)
  end

  def restore!
    OptionalColumnsSchema.restore!(COLUMNS)
  end
end

# The person behind a key (0.7.0).
module CreatedBySchema
  COLUMNS = {
    created_by_type: [:string, {}],
    created_by_id: [:bigint, {}]
  }.freeze

  module_function

  def without_columns(&block)
    OptionalColumnsSchema.without(COLUMNS, &block)
  end
end

# The durable one-time token handoff column.
module TokenShownAtSchema
  COLUMNS = { token_shown_at: [:datetime, {}] }.freeze

  module_function

  def without_column(&block)
    OptionalColumnsSchema.without(COLUMNS, &block)
  end
end

# Simple User model for testing associations
class User < ActiveRecord::Base
  # Simulate including the concern for testing purposes
  include ApiKeys::Models::Concerns::HasApiKeys
  has_api_keys # Basic association
end

# Base class for ApiKeys tests
class ApiKeys::Test < ActiveSupport::TestCase
  include ActiveSupport::Testing::TimeHelpers

  # Reset configuration before each test
  def setup
    ApiKeys.reset_configuration!
    token_session_key = "t" * ActiveSupport::MessageEncryptor.key_len("aes-256-gcm")
    @token_session_encryptor = ActiveSupport::MessageEncryptor.new(
      token_session_key,
      cipher: "aes-256-gcm",
      serializer: JSON
    )
    ApiKeys::TokenSession.stubs(:token_encryptor).returns(@token_session_encryptor)
    # Clear any existing records between tests
    ApiKeys::IdempotencyKey.delete_all
    ApiKeys::DeviceAuthorization.delete_all
    ApiKeys::ApiKey.delete_all
    User.delete_all
  end

  # Helper to assert that a block raises a specific ApiKeys error
  def assert_api_keys_error(expected_error_class = ApiKeys::Error, &block)
    assert_raises(expected_error_class, &block)
  end

  def teardown
    ApiKeys::IdempotencyKey.delete_all
    ApiKeys::DeviceAuthorization.delete_all
    ApiKeys::ApiKey.delete_all
    User.delete_all
  end

  # Temporarily set the configured hash strategy for the duration of the block
  # Ensures the original strategy is restored afterwards
  def with_hash_strategy(strategy)
    original = ApiKeys.configuration.hash_strategy
    ApiKeys.configuration.hash_strategy = strategy
    yield
  ensure
    ApiKeys.configuration.hash_strategy = original
  end
end

puts "Test helper setup complete."
