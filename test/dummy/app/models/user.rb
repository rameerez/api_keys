class User < ApplicationRecord
  # Add the core ApiKeys functionality
  has_api_keys do
    # require_name true
    max_keys 10
    default_scopes %w[read write]
  end

end
