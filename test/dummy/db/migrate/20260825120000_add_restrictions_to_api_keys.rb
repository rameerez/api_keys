# frozen_string_literal: true

# Keep the demo application's schema aligned with the request restrictions
# feature added in api_keys 0.5. Existing downstream applications use the
# corresponding `api_keys:add_restrictions` generator when opting into it.
class AddRestrictionsToApiKeys < ActiveRecord::Migration[8.0]
  def change
    add_column :api_keys, :restrictions, :json, default: {}, null: false
  end
end
