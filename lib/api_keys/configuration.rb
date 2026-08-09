# frozen_string_literal: true

require "active_support/core_ext/numeric/time"
require "active_support/core_ext/string/inflections"
require "active_support/security_utils"

module ApiKeys
  # Defines the configuration options for the ApiKeys gem.
  # These options can be set in an initializer, e.g., config/initializers/api_keys.rb
  class Configuration
    # Default empty callback proc
    DEFAULT_CALLBACK = ->(_context){}.freeze
    DEFAULT_PARENT_CONTROLLER = "::ApplicationController"

    # == Accessors ==

    # Core Authentication
    attr_reader :header, :query_param

    # Token Generation
    attr_reader :token_prefix, :token_length, :token_alphabet

    # Storage & Verification
    attr_reader :hash_strategy
    attr_reader :secure_compare_proc
    attr_accessor :key_store_adapter, :policy_provider

    # Engine Configuration
    attr_reader :parent_controller

    # Owner Context Configuration
    attr_reader :current_owner_method, :authenticate_owner_method

    # Optional Behaviors
    attr_reader :default_max_keys_per_owner, :require_key_name
    attr_reader :expire_after, :default_scopes, :track_requests_count

    # Performance
    attr_reader :cache_ttl, :stats_update_interval

    # Security
    attr_reader :https_only_production, :https_strict_mode

    # Tenant Resolution
    attr_reader :tenant_resolver

    # Callbacks (Placeholders for future extension)
    attr_reader :before_authentication, :after_authentication

    # Background Job Queues
    attr_reader :stats_job_queue, :callbacks_job_queue

    # Global Async Toggle
    attr_reader :enable_async_operations

    # Engine UI Configuration
    attr_accessor :return_url, :return_text

    # Debugging
    attr_reader :debug_logging

    # Key Types & Environments (Stripe-style publishable/secret keys)
    #
    # @!attribute [rw] key_types
    #   @return [Hash] Key type definitions. Each key type has:
    #     - :prefix [String] Token prefix (e.g., "pk" → pk_test_)
    #     - :permissions [Array<String>, :all] Scope ceiling for this type
    #     - :revocable [Boolean] Whether keys can be revoked (default: true)
    #     - :limit [Integer, nil] Max keys per owner per environment (nil = unlimited)
    #     - :public [Boolean] If true AND revocable: false, store plaintext token in
    #       metadata so it can be viewed again in dashboard. Use ONLY for publishable
    #       keys that are designed to be embedded in distributed apps. (default: false)
    #   @example
    #     config.key_types = {
    #       publishable: { prefix: "pk", permissions: %w[read], revocable: false, public: true, limit: 1 },
    #       secret: { prefix: "sk", permissions: :all }
    #     }
    #
    # @!attribute [rw] environments
    #   @return [Hash] Environment definitions. Each environment has:
    #     - :prefix_segment [String, nil] Middle part of prefix (e.g., "test" → pk_test_)
    #   @example
    #     config.environments = { test: { prefix_segment: "test" }, live: { prefix_segment: "live" } }
    #
    # @!attribute [rw] current_environment
    #   @return [Proc, Symbol] Lambda or symbol returning current environment
    #   @example
    #     config.current_environment = -> { Rails.env.production? ? :live : :test }
    #
    # @!attribute [rw] strict_environment_isolation
    #   @return [Boolean] If true, keys only work in their matching environment
    #
    # @!attribute [rw] default_key_type
    #   @return [Symbol, nil] Default key type when not specified in create_api_key!
    #   @example
    #     config.default_key_type = :secret
    #
    # @!attribute [rw] dashboard_allow_cross_environment
    #   @return [Boolean] If true, dashboard shows keys from all environments.
    #     If false (default), dashboard only shows keys matching current_environment.
    #   @example
    #     config.dashboard_allow_cross_environment = false
    attr_reader :environments, :current_environment, :strict_environment_isolation,
                :default_key_type, :dashboard_allow_cross_environment

    # Custom writer for key_types that validates prefix uniqueness
    attr_reader :key_types

    VALID_HASH_STRATEGIES = %i[sha256 bcrypt].freeze
    VALID_TOKEN_ALPHABETS = %i[base58 hex].freeze
    TOKEN_LENGTH_RANGE = (16..64)
    MAX_CONFIGURED_SCOPES = 100
    CONFIG_NAME_PATTERN = /\A[a-zA-Z0-9_-]{1,64}\z/
    HTTP_HEADER_PATTERN = /\A[!#$%&'*+\-.^_`|~0-9A-Za-z]{1,128}\z/
    QUERY_PARAM_PATTERN = /\A[a-zA-Z0-9_.~-]{1,128}\z/
    METHOD_NAME_PATTERN = /\A[a-zA-Z_]\w*[!?]?\z/
    CONSTANT_NAME_PATTERN = /\A(?:::)?[A-Z]\w*(?:::[A-Z]\w*)*\z/
    BOOLEAN_SETTINGS = %i[
      require_key_name track_requests_count https_only_production https_strict_mode
      enable_async_operations debug_logging strict_environment_isolation
      dashboard_allow_cross_environment
    ].freeze

    def header=(value)
      unless value.nil? || (value.is_a?(String) && value.match?(HTTP_HEADER_PATTERN))
        raise ArgumentError, "header must be nil or a valid HTTP header name of at most 128 characters"
      end

      @header = value&.dup&.freeze
    end

    def query_param=(value)
      unless value.nil? || (value.is_a?(String) && value.match?(QUERY_PARAM_PATTERN))
        raise ArgumentError, "query_param must be nil or a safe parameter name of at most 128 characters"
      end

      @query_param = value&.dup&.freeze
    end

    def default_max_keys_per_owner=(value)
      unless value.nil? || (value.is_a?(Integer) && value >= 0)
        raise ArgumentError, "default_max_keys_per_owner must be a non-negative Integer or nil"
      end

      @default_max_keys_per_owner = value
    end

    def expire_after=(value)
      unless value.nil?
        seconds = value.to_f if value.respond_to?(:to_f)
        valid = value.respond_to?(:from_now) && seconds&.finite? && seconds.positive?
        raise ArgumentError, "expire_after must be a positive duration or nil" unless valid
      end

      @expire_after = value
    end

    def default_scopes=(value)
      unless value.is_a?(Array) && value.length <= MAX_CONFIGURED_SCOPES && value.all? { |scope| valid_scope_name?(scope) }
        raise ArgumentError, "default_scopes must be a bounded Array of safe scope strings"
      end

      @default_scopes = deep_copy_and_freeze(value.uniq)
    end

    def cache_ttl=(value)
      unless value.nil?
        seconds = value.to_f if value.respond_to?(:to_f)
        valid = (value.is_a?(Numeric) || value.respond_to?(:from_now)) && seconds&.finite? && !seconds.negative?
        raise ArgumentError, "cache_ttl must be a finite non-negative duration/number or nil" unless valid
      end

      @cache_ttl = value
    end

    def stats_update_interval=(value)
      unless value.nil?
        seconds = value.to_f if value.respond_to?(:to_f)
        valid = (value.is_a?(Numeric) || value.respond_to?(:from_now)) && seconds&.finite? && !seconds.negative?
        raise ArgumentError, "stats_update_interval must be a finite non-negative duration/number or nil" unless valid
      end

      @stats_update_interval = value
    end

    def parent_controller=(value)
      valid = value.is_a?(Class) || (value.is_a?(String) && value.match?(CONSTANT_NAME_PATTERN))
      raise ArgumentError, "parent_controller must be a controller Class or a valid constant name" unless valid

      @parent_controller = value.is_a?(String) ? value.dup.freeze : value
      @parent_controller_explicitly_configured = true
    end

    def parent_controller_class
      candidate = if !@parent_controller_explicitly_configured && defined?(ApiKeys::Engine) &&
                     ApiKeys::Engine.config.parent_controller.present?
                    ApiKeys::Engine.config.parent_controller
                  else
                    parent_controller
                  end
      candidate.is_a?(Class) ? candidate : candidate.constantize
    end

    BOOLEAN_SETTINGS.each do |setting|
      define_method("#{setting}=") do |value|
        raise ArgumentError, "#{setting} must be true or false" unless value == true || value == false

        instance_variable_set("@#{setting}", value)
      end
    end

    def before_authentication=(value)
      validate_callback!(value, :before_authentication)
      @before_authentication = value
    end

    def after_authentication=(value)
      validate_callback!(value, :after_authentication)
      @after_authentication = value
    end

    def tenant_resolver=(value)
      raise ArgumentError, "tenant_resolver must be callable" unless value.respond_to?(:call)

      @tenant_resolver = value
    end

    def secure_compare_proc=(value)
      raise ArgumentError, "secure_compare_proc must be callable" unless value.respond_to?(:call)

      @secure_compare_proc = value
    end

    def stats_job_queue=(value)
      @stats_job_queue = validate_queue_name!(value, :stats_job_queue)
    end

    def callbacks_job_queue=(value)
      @callbacks_job_queue = validate_queue_name!(value, :callbacks_job_queue)
    end

    def current_owner_method=(value)
      @current_owner_method = validate_method_name!(value, :current_owner_method)
    end

    def authenticate_owner_method=(value)
      @authenticate_owner_method = validate_method_name!(value, :authenticate_owner_method)
    end

    def current_environment=(value)
      unless value.nil? || value.respond_to?(:call) || valid_config_name?(value)
        raise ArgumentError, "current_environment must be callable, a safe String/Symbol, or nil"
      end

      @current_environment = value
    end

    def default_key_type=(value)
      unless value.nil? || valid_config_name?(value)
        raise ArgumentError, "default_key_type must be a safe String/Symbol or nil"
      end

      @default_key_type = value
    end

    def token_prefix=(value)
      unless value.is_a?(String) || value.respond_to?(:call)
        raise ArgumentError, "token_prefix must be a String or callable object"
      end

      validate_resolved_prefix!(value) if value.is_a?(String)
      @token_prefix = value
    end

    def resolved_token_prefix
      value = @token_prefix.respond_to?(:call) ? @token_prefix.call : @token_prefix
      validate_resolved_prefix!(value)
      value
    end

    def token_length=(value)
      unless value.is_a?(Integer) && TOKEN_LENGTH_RANGE.cover?(value)
        raise ArgumentError, "token_length must be an Integer between #{TOKEN_LENGTH_RANGE.begin} and #{TOKEN_LENGTH_RANGE.end}"
      end

      @token_length = value
    end

    def token_alphabet=(value)
      unless VALID_TOKEN_ALPHABETS.include?(value)
        raise ArgumentError, "token_alphabet must be one of: #{VALID_TOKEN_ALPHABETS.join(', ')}"
      end

      @token_alphabet = value
    end

    def hash_strategy=(value)
      unless VALID_HASH_STRATEGIES.include?(value)
        raise ArgumentError, "hash_strategy must be one of: #{VALID_HASH_STRATEGIES.join(', ')}"
      end

      @hash_strategy = value
    end

    # Sets the key types configuration with prefix collision validation.
    # @param value [Hash] Key type definitions
    # @raise [ArgumentError] If multiple key types share the same prefix
    def key_types=(value)
      raise ArgumentError, "key_types must be a Hash" unless value.is_a?(Hash)

      validate_key_types!(value)
      validate_composite_prefixes!(value, @environments || {})
      @key_types = deep_copy_and_freeze(value)
    end

    def environments=(value)
      raise ArgumentError, "environments must be a Hash" unless value.is_a?(Hash)

      value.each do |name, environment_config|
        validate_config_name!(name, "environment")
        raise ArgumentError, "Environment '#{name}' configuration must be a Hash" unless environment_config.is_a?(Hash)

        segment = environment_config[:prefix_segment]
        validate_config_name!(segment, "environment prefix segment") unless segment.nil?
      end
      validate_duplicate_config_names!(value, "environment")
      validate_composite_prefixes!(@key_types || {}, value)
      @environments = deep_copy_and_freeze(value)
    end

    private

    def validate_resolved_prefix!(prefix)
      valid = prefix.is_a?(String) && prefix.present? && prefix.valid_encoding? && prefix.bytesize <= 64 &&
        prefix.each_codepoint.none? { |codepoint| codepoint <= 0x20 || codepoint == 0x7f }
      return if valid

      raise ArgumentError, "token_prefix must resolve to a non-blank string of at most 64 bytes without whitespace or control characters"
    rescue ArgumentError
      raise ArgumentError, "token_prefix must resolve to a non-blank string of at most 64 bytes without whitespace or control characters"
    end

    def validate_key_types!(key_types_hash)
      validate_duplicate_config_names!(key_types_hash, "key type")

      key_types_hash.each do |name, type_config|
        validate_config_name!(name, "key type")
        raise ArgumentError, "Key type '#{name}' configuration must be a Hash" unless type_config.is_a?(Hash)

        validate_config_name!(type_config[:prefix], "key type prefix")
        permissions = type_config[:permissions]
        unless permissions == :all || permissions.is_a?(Array)
          raise ArgumentError, "Key type '#{name}' permissions must be :all or an Array of strings"
        end
        if permissions.is_a?(Array) && permissions.length > MAX_CONFIGURED_SCOPES
          raise ArgumentError, "Key type '#{name}' permissions cannot contain more than #{MAX_CONFIGURED_SCOPES} entries"
        end
        if permissions.is_a?(Array) && permissions.any? { |permission| !valid_scope_name?(permission) }
          raise ArgumentError, "Key type '#{name}' permissions must contain only non-blank strings of at most 128 bytes"
        end

        %i[revocable public].each do |setting|
          next unless type_config.key?(setting)
          next if [true, false].include?(type_config[setting])

          raise ArgumentError, "Key type '#{name}' #{setting} must be true or false"
        end

        limit = type_config[:limit]
        if !limit.nil? && (!limit.is_a?(Integer) || limit <= 0)
          raise ArgumentError, "Key type '#{name}' limit must be a positive Integer or nil"
        end

        next unless type_config[:public] == true

        unless type_config[:revocable] == false
          raise ArgumentError, "Public key type '#{name}' must explicitly set revocable: false"
        end
        unless permissions.is_a?(Array) && permissions.any?
          raise ArgumentError, "Public key type '#{name}' must have a finite, non-empty permissions list"
        end
      end

      validate_key_type_prefixes!(key_types_hash)
    end

    def validate_config_name!(value, label)
      return if valid_config_name?(value)

      raise ArgumentError, "#{label} must contain only letters, numbers, underscores, or hyphens (1-64 characters)"
    end

    def valid_config_name?(value)
      (value.is_a?(String) || value.is_a?(Symbol)) && value.to_s.match?(CONFIG_NAME_PATTERN)
    end

    def valid_scope_name?(value)
      value.is_a?(String) && value.present? && value.valid_encoding? && value.bytesize <= 128 &&
        value.each_codepoint.none? { |codepoint| codepoint <= 0x20 || codepoint == 0x7f }
    rescue ArgumentError
      false
    end

    # Validates that all key type prefixes are unique to prevent token collision
    def validate_key_type_prefixes!(key_types_hash)
      prefixes = key_types_hash.map { |_type, config| config[:prefix].to_s }.compact
      duplicates = prefixes.group_by(&:itself).select { |_k, v| v.size > 1 }.keys

      if duplicates.any?
        raise ArgumentError, "Key type prefixes must be unique. Duplicate prefix(es): #{duplicates.join(', ')}"
      end
    end

    def validate_duplicate_config_names!(configuration, label)
      duplicates = configuration.keys.map(&:to_s).group_by(&:itself).select { |_name, names| names.length > 1 }.keys
      return if duplicates.empty?

      raise ArgumentError, "#{label} names must be unique after string normalization: #{duplicates.join(', ')}"
    end

    def validate_composite_prefixes!(key_types, environments)
      return if key_types.empty?

      environment_entries = environments.empty? ? [[nil, {}]] : environments.to_a
      combinations = key_types.flat_map do |type_name, type_config|
        environment_entries.map do |environment_name, environment_config|
          segment = environment_config[:prefix_segment]
          prefix = segment.nil? ? "#{type_config[:prefix]}_" : "#{type_config[:prefix]}_#{segment}_"
          [prefix, "#{type_name}/#{environment_name || 'default'}"]
        end
      end
      collisions = combinations.group_by(&:first).select { |_prefix, entries| entries.length > 1 }
      return if collisions.empty?

      details = collisions.map { |prefix, entries| "#{prefix} (#{entries.map(&:last).join(', ')})" }.join("; ")
      raise ArgumentError, "Key type/environment prefixes must be unique: #{details}"
    end

    def validate_callback!(value, setting)
      raise ArgumentError, "#{setting} must be a Proc" unless value.is_a?(Proc)
    end

    def validate_queue_name!(value, setting)
      unless (value.is_a?(String) || value.is_a?(Symbol)) && value.to_s.match?(/\A[a-zA-Z0-9_-]{1,128}\z/)
        raise ArgumentError, "#{setting} must be a safe String or Symbol"
      end

      value
    end

    def validate_method_name!(value, setting)
      unless value.nil? || ((value.is_a?(String) || value.is_a?(Symbol)) && value.to_s.match?(METHOD_NAME_PATTERN))
        raise ArgumentError, "#{setting} must be a valid method name or nil"
      end

      value
    end

    def deep_copy_and_freeze(value)
      copied = case value
               when Hash
                 value.to_h { |key, nested_value| [deep_copy_and_freeze(key), deep_copy_and_freeze(nested_value)] }
               when Array
                 value.map { |nested_value| deep_copy_and_freeze(nested_value) }
               when String
                 value.dup
               else
                 value
               end
      copied.freeze
    end

    public

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
      # TODO: Define and implement ApiKeys::BasePolicy in later versions
      # This will define the authorization policy class used to check if a key is valid beyond basic checks.
      # Allows injecting custom logic (IP allow-listing, time-of-day checks, etc.).
      # Must be a class name (String or Class) responding to `.new(api_key, request).valid?`
      # Default: "ApiKeys::BasePolicy" (a basic implementation should be provided)
      @policy_provider = "ApiKeys::BasePolicy" # Default authorization policy class name

      # Engine Configuration
      @parent_controller = DEFAULT_PARENT_CONTROLLER
      @parent_controller_explicitly_configured = false

      # Owner Context Configuration
      @current_owner_method = :current_user # Default to current_user for backward compatibility
      @authenticate_owner_method = :authenticate_user! # Default to authenticate_user! for Devise compatibility

      # Optional Behaviors
      @default_max_keys_per_owner = nil # No global key limit per owner
      @require_key_name = false # Don't require names for keys globally
      @expire_after = nil # Keys do not expire by default (e.g., 90.days)
      @default_scopes = [].freeze # No default scopes assigned globally

      # Performance
      @cache_ttl = 5.seconds # Good balance: fast revocation, mostly-cached – still allows most repeated requests to benefit from cache
      @stats_update_interval = 1.minute # Debounce last_used_at writes unless exact request counting is enabled

      # Security
      @https_only_production = true # Warn if used over HTTP in production
      @https_strict_mode = true # Fail closed if a production request is not HTTPS

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

      # Key Types & Environments (default to empty/disabled for backwards compatibility)
      @key_types = {}.freeze  # Empty = feature disabled, legacy behavior
      @environments = {}.freeze  # Empty = no environment-based prefixes
      @current_environment = -> { :default }  # Default environment detection
      @strict_environment_isolation = false  # Don't enforce environment isolation by default
      @default_key_type = nil  # No default key type (must be specified explicitly)
      @dashboard_allow_cross_environment = false  # Dashboard shows only current environment's keys
    end
  end
end
