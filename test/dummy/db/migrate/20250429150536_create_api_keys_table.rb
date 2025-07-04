# frozen_string_literal: true

# Migration responsible for creating the core api_keys table.
class CreateApiKeysTable < ActiveRecord::Migration[8.0]
  def change
    primary_key_type, foreign_key_type = primary_and_foreign_key_types

    create_table :api_keys, id: primary_key_type do |t|
      # Identifiable prefix (e.g., "ak_live_", "ak_test_") for env/debugging
      t.string   :prefix,        null: false

      # Secure, salted digest of the token (e.g., bcrypt hash, 60 chars)
      t.string   :token_digest,  null: false

      # Algorithm used for the digest (e.g., "bcrypt", "sha256")
      t.string   :digest_algorithm, null: false

      # Last 4 characters of the random part of the token for display
      t.string   :last4,            null: false, limit: 4

      # Optional, user-provided name for the key
      t.string   :name

      # Who owns this key? Can be null for ownerless keys.
      t.references :owner, polymorphic: true, null: true, type: foreign_key_type

      # Optional list of permissions granted to this key (array of strings)
      t.send(json_column_type, :scopes, default: [], null: false)

      # Optional freeform metadata for tagging
      t.send(json_column_type, :metadata, default: {}, null: false)

      # Optional auto-expiration timestamp
      t.datetime :expires_at

      # Timestamp of the last successful authentication using this key
      t.datetime :last_used_at

      # Optional counter cache for total requests made with this key.
      t.bigint   :requests_count, default: 0, null: false

      # Timestamp when the key was revoked (null means active)
      t.datetime :revoked_at

      t.timestamps

      # Critical index for authentication performance
      t.index :token_digest, unique: true

      # Index to optimize prefix-based lookups (especially for bcrypt)
      t.index [:prefix, :digest_algorithm], name: "index_api_keys_on_prefix_and_digest_algorithm"

      # Optional indexes
      t.index :prefix
      t.index :last4 # Index potentially useful for UI lookups/filtering by masked token
      t.index :owner_id if foreign_key_type # Index owner_id only if it's a separate column
      t.index :owner_type if foreign_key_type # Index owner_type only if it's a separate column
      t.index :expires_at
      t.index :revoked_at
      t.index :last_used_at
    end
  end

  private

  # Helper method to determine the appropriate primary and foreign key types
  # based on the Rails application's configuration.
  def primary_and_foreign_key_types
    config = Rails.configuration.generators
    setting = config.options[config.orm][:primary_key_type]
    primary_key_type = setting || :primary_key
    foreign_key_type = setting || :bigint # Assuming bigint is a safe default for foreign keys
    [primary_key_type, foreign_key_type]
  end

  # Helper method to determine the appropriate JSON column type based on the database adapter.
  # Uses :jsonb for PostgreSQL for better performance and indexing, :json otherwise.
  def json_column_type
    # Check connection availability for adapter name inspection
    if ActiveRecord::Base.connection.adapter_name.downcase.include?('postgresql')
      :jsonb
    else
      :json
    end
  rescue ActiveRecord::ConnectionNotEstablished
    # Fallback during initial setup or if connection isn't available
    :text
  end

  # Provides the appropriate migration version syntax for the current Rails version.
  def migration_version
    major = ActiveRecord::VERSION::MAJOR
    minor = ActiveRecord::VERSION::MINOR
    if major >= 5
      "[#{major}.#{minor}]"
    else
      ""
    end
  end
end
