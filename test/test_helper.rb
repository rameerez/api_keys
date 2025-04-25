# frozen_string_literal: true

$LOAD_PATH.unshift File.expand_path("../lib", __dir__)
require "apikeys"

# Core testing libraries
require "minitest/autorun"
require "minitest/reporters"
require "mocha/minitest"

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
    t.timestamps

    t.index :token_digest, unique: true
    t.index :prefix
    t.index [:owner_type, :owner_id]
    t.index :expires_at
    t.index :revoked_at
    t.index :last_used_at
  end
end

puts "Database schema loaded."

# Simple User model for testing associations
class User < ActiveRecord::Base
  # Simulate including the concern for testing purposes
  include Apikeys::Models::Concerns::HasApiKeys
  has_api_keys # Basic association
end

# Base class for Apikeys tests
class Apikeys::Test < Minitest::Test
  # Reset configuration before each test
  def setup
    Apikeys.reset_configuration!
    # Clear any existing records between tests
    Apikeys::ApiKey.delete_all
    User.delete_all
  end

  # Helper to assert that a block raises a specific Apikeys error
  def assert_apikeys_error(expected_error_class = Apikeys::Error, &block)
    assert_raises(expected_error_class, &block)
  end

  def teardown
    Apikeys::ApiKey.delete_all
    User.delete_all
  end
end

puts "Test helper setup complete."
