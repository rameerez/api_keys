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

    # Owner Context Configuration
    attr_accessor :current_owner_method, :authenticate_owner_method

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
      @hash_strategy = :sha256 # sha256 or :bcrypt
      @secure_compare_proc = ->(a, b) { ActiveSupport::SecurityUtils.secure_compare(a, b) }
      @key_store_adapter = :active_record # Default storage backend
      @policy_provider = "ApiKeys::BasePolicy" # Default authorization policy class name

      # Engine Configuration
      @parent_controller = '::ApplicationController'

      # Owner Context Configuration
      @current_owner_method = :current_user
      @authenticate_owner_method = :authenticate_user!

      # Optional Behaviors
      @default_max_keys_per_owner = nil
      @require_key_name = false
      @expire_after = nil
      @default_scopes = []

      # Performance
      @cache_ttl = 5.seconds

      # Security
      @https_only_production = true
      @https_strict_mode = false

      # Background Job Queues
      @stats_job_queue = :default
      @callbacks_job_queue = :default

      # Global Async Toggle
      @enable_async_operations = true

      # Usage Statistics
      @track_requests_count = false

      # Callbacks
      @before_authentication = DEFAULT_CALLBACK
      @after_authentication = DEFAULT_CALLBACK

      # Engine UI Configuration
      @return_url = "/"
      @return_text = "‹ Home"

      # Debugging
      @debug_logging = false

      # Tenant Resolution
      @tenant_resolver = ->(api_key) { api_key.owner if api_key.respond_to?(:owner) }
    end
  end
end
