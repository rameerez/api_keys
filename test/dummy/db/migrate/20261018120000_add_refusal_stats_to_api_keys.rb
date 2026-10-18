# frozen_string_literal: true

# Keep the demo application's schema aligned with the refused-traffic statistics
# added in api_keys 0.6. Existing downstream applications use the corresponding
# `api_keys:add_refusal_stats` generator when upgrading.
class AddRefusalStatsToApiKeys < ActiveRecord::Migration[8.0]
  def change
    add_column :api_keys, :last_refused_at, :datetime
    add_column :api_keys, :refusals_count, :bigint, default: 0, null: false
    add_column :api_keys, :last_refusal_code, :string, limit: 64
  end
end
