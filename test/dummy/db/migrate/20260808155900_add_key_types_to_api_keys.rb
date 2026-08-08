# frozen_string_literal: true

# Keep the demo application's schema aligned with the key-types feature added
# in api_keys 0.3. Existing downstream applications use the corresponding
# `api_keys:add_key_types` generator when opting into this feature.
class AddKeyTypesToApiKeys < ActiveRecord::Migration[8.0]
  def change
    add_column :api_keys, :key_type, :string
    add_column :api_keys, :environment, :string

    add_index :api_keys, :key_type
    add_index :api_keys, :environment
    add_index :api_keys, [:owner_type, :owner_id, :key_type, :environment],
              name: "index_api_keys_owner_type_env"
  end
end
