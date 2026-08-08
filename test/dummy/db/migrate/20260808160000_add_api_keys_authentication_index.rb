# frozen_string_literal: true

class AddApiKeysAuthenticationIndex < ActiveRecord::Migration[8.0]
  def change
    add_index :api_keys,
              %i[prefix last4 digest_algorithm],
              name: "index_api_keys_authentication_lookup"
  end
end
