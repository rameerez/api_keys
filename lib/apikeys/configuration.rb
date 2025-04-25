# frozen_string_literal: true

require "active_support/core_ext/numeric/time"
require "active_support/security_utils"

module Apikeys
  # Defines the configuration options for the Apikeys gem.
  # These options can be set in an initializer, e.g., config/initializers/apikeys.rb
  class Configuration
    # == Accessors ==

    # Core Authentication
    attr_accessor :header, :query_param

    # Token Generation
    attr_accessor :env_prefix_map, :token_prefix, :token_length, :token_alphabet

    # Storage & Verification
    attr_accessor :hash_strategy, :secure_compare_proc, :key_store_adapter, :policy_provider

    # Optional Behaviors
    attr_accessor :expire_after, :default_scopes, :track_requests_count
    attr_accessor :default_max_keys_per_owner, :require_key_name

    # Performance
    attr_accessor :cache_ttl

    # Security
    attr_accessor :https_only_production, :https_strict_mode

    # Tenant Resolution
    attr_accessor :tenant_resolver

    # Callbacks (Placeholders for future extension)
    attr_accessor :before_authentication, :after_authentication

    # == Initialization ==

    def initialize
      set_defaults
    end

    private

    def set_defaults
      # Core Authentication
      @header = "Authorization" # Expects "Bearer <token>"
      @query_param = nil # No query param lookup by default

      # Token Generation
      @env_prefix_map = { production: "live", development: "test", test: "test" }
      @token_prefix = -> { "ak_#{env_prefix_map.fetch(Rails.env.to_sym, Rails.env)}_" }
      @token_length = 24 # Bytes of entropy
      @token_alphabet = :base58 # Avoid ambiguous chars (0, O, I, l)

      # Storage & Verification
      @hash_strategy = :bcrypt # Recommended: :bcrypt or :sha256
      @secure_compare_proc = ->(a, b) { ActiveSupport::SecurityUtils.secure_compare(a, b) }
      @key_store_adapter = :active_record # Default storage backend
      # TODO: Define Apikeys::BasePolicy later
      @policy_provider = "Apikeys::BasePolicy" # Default authorization policy class name

      # Optional Behaviors
      @expire_after = nil # Keys do not expire by default (e.g., 90.days)
      @default_scopes = [] # No default scopes assigned globally
      @track_requests_count = false # Don't increment `requests_count` by default
      @default_max_keys_per_owner = nil # No global key limit per owner
      @require_key_name = false # Don't require names for keys globally

      # Performance
      @cache_ttl = 10.seconds # Cache key lookups for 10 seconds (0 to disable)

      # Security
      @https_only_production = true # Warn if used over HTTP in production
      @https_strict_mode = false # Don't raise error, just warn

      # Tenant Resolution
      @tenant_resolver = ->(api_key) { api_key.owner if api_key.respond_to?(:owner) }

      # Callbacks
      @before_authentication = ->(_request) { }
      @after_authentication = ->(_result) { }
    end
  end
end
