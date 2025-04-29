# frozen_string_literal: true

require "active_support/core_ext/numeric/time"
require "active_support/security_utils"

module ApiKeys
  # Defines the configuration options for the ApiKeys gem.
  # These options can be set in an initializer, e.g., config/initializers/api_keys.rb
  class Configuration
    # Default empty callback proc
    DEFAULT_CALLBACK = ->(_context){}.freeze

    # == Accessors ==

    # Core Authentication
    attr_accessor :header, :query_param

    # Token Generation
    attr_accessor :token_prefix, :token_length, :token_alphabet

    # Storage & Verification
    attr_accessor :hash_strategy, :secure_compare_proc, :key_store_adapter, :policy_provider

    # Engine Configuration
    attr_accessor :parent_controller

    # Optional Behaviors
    attr_accessor :default_max_keys_per_owner, :require_key_name
    attr_accessor :expire_after, :default_scopes, :track_requests_count

    # Performance
    attr_accessor :cache_ttl

    # Security
    attr_accessor :https_only_production, :https_strict_mode

    # Tenant Resolution
    attr_accessor :tenant_resolver

    # Callbacks (Placeholders for future extension)
    attr_accessor :before_authentication, :after_authentication

    # Background Job Queues
    attr_accessor :stats_job_queue, :callbacks_job_queue

    # Global Async Toggle
    attr_accessor :enable_async_operations

    # Engine UI Configuration
    attr_accessor :return_url, :return_text

    # Debugging
    attr_accessor :debug_logging

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
      @token_prefix = -> { "ak_" }
      @token_length = 24 # Bytes of entropy
      @token_alphabet = :base58 # Avoid ambiguous chars (0, O, I, l)

      # Storage & Verification
      @hash_strategy = :bcrypt # Recommended: :bcrypt or :sha256
      @secure_compare_proc = ->(a, b) { ActiveSupport::SecurityUtils.secure_compare(a, b) }
      @key_store_adapter = :active_record # Default storage backend
      # TODO: Define and implement ApiKeys::BasePolicy in later versions
      # This will define the authorization policy class used to check if a key is valid beyond basic checks.
      # Allows injecting custom logic (IP allow-listing, time-of-day checks, etc.).
      # Must be a class name (String or Class) responding to `.new(api_key, request).valid?`
      # Default: "ApiKeys::BasePolicy" (a basic implementation should be provided)
      @policy_provider = "ApiKeys::BasePolicy" # Default authorization policy class name

      # Engine Configuration
      @parent_controller = '::ApplicationController'

      # Optional Behaviors
      @default_max_keys_per_owner = nil # No global key limit per owner
      @require_key_name = false # Don't require names for keys globally
      @expire_after = nil # Keys do not expire by default (e.g., 90.days)
      @default_scopes = [] # No default scopes assigned globally

      # Performance
      @cache_ttl = 5.minutes # More sensible default TTL for authentication caching

      # Security
      @https_only_production = true # Warn if used over HTTP in production
      @https_strict_mode = false # Don't raise error, just warn

      # Background Job Queues
      @stats_job_queue = :default
      @callbacks_job_queue = :default

      # Global Async Toggle
      @enable_async_operations = true # Default to true to enable jobs

      # Usage Statistics
      @track_requests_count = false # Don't increment `requests_count` by default

      # Callbacks
      @before_authentication = DEFAULT_CALLBACK
      @after_authentication = DEFAULT_CALLBACK

      # Engine UI Configuration
      @return_url = "/" # Default fallback path
      @return_text = "‹ Home" # Default link text

      # Debugging
      @debug_logging = false # Disable debug logging by default (warn and error get logged regardless of this)

      # Tenant Resolution
      @tenant_resolver = ->(api_key) { api_key.owner if api_key.respond_to?(:owner) }
    end
  end
end
