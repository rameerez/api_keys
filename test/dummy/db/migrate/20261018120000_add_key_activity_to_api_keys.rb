# frozen_string_literal: true

# Keep the demo application's schema aligned with the columns added in
# api_keys 0.6: refused-traffic statistics and the durable one-time token
# handoff. Existing downstream applications use the corresponding
# `api_keys:add_key_activity` generator when upgrading.
class AddKeyActivityToApiKeys < ActiveRecord::Migration[8.0]
  def change
    add_column :api_keys, :last_refused_at, :datetime
    add_column :api_keys, :refusals_count, :bigint, default: 0, null: false
    add_column :api_keys, :last_refusal_code, :string, limit: 64
    add_column :api_keys, :token_shown_at, :datetime
  end
end
