# frozen_string_literal: true

ENV["RAILS_ENV"] ||= "test"
$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "api_keys"

# Core testing libraries
require "minitest/autorun"
require "minitest/reporters"
require "mocha/minitest"

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
    t.text     :scopes, default: "[]", null: false # Use text for SQLite JSON
    t.text     :metadata, default: "{}", null: false # Use text for SQLite JSON
    t.datetime :expires_at
    t.datetime :last_used_at
    t.bigint   :requests_count, default: 0, null: false
    t.datetime :revoked_at
    t.string   :last4, null: false, default: ""
    t.timestamps

    t.index :token_digest, unique: true
    t.index :prefix
    t.index [:owner_type, :owner_id]
    t.index :expires_at
    t.index :revoked_at
    t.index :last_used_at
  end
end

# Mirror engine initializer behavior for attribute casting in tests
json_col_type = :json
ApiKeys::ApiKey.attribute :scopes, json_col_type, default: []
ApiKeys::ApiKey.attribute :metadata, json_col_type, default: {}

puts "Database schema loaded."

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
    # Clear any existing records between tests
    ApiKeys::ApiKey.delete_all
    User.delete_all
  end

  # Helper to assert that a block raises a specific ApiKeys error
  def assert_api_keys_error(expected_error_class = ApiKeys::Error, &block)
    assert_raises(expected_error_class, &block)
  end

  def teardown
    ApiKeys::ApiKey.delete_all
    User.delete_all
  end
end

puts "Test helper setup complete."
