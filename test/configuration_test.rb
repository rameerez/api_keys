# frozen_string_literal: true

require "test_helper"

module ApiKeys
  class ConfigurationTest < ApiKeys::Test
    test "security-sensitive defaults fail closed" do
      assert ApiKeys.configuration.https_only_production
      assert ApiKeys.configuration.https_strict_mode
      assert_nil ApiKeys.configuration.query_param
      assert_equal 1.minute, ApiKeys.configuration.stats_update_interval
    end

    test "validates token generation configuration when assigned" do
      assert_raises(ArgumentError) { ApiKeys.configuration.token_length = 0 }
      assert_raises(ArgumentError) { ApiKeys.configuration.token_length = 1_000_000 }
      assert_raises(ArgumentError) { ApiKeys.configuration.token_alphabet = :words }
      assert_raises(ArgumentError) { ApiKeys.configuration.hash_strategy = :md5 }
      assert_raises(ArgumentError) { ApiKeys.configuration.token_prefix = "bad prefix" }
    end

    test "accepts string and callable token prefixes" do
      ApiKeys.configuration.token_prefix = "service_"
      assert_equal "service_", ApiKeys.configuration.resolved_token_prefix

      ApiKeys.configuration.token_prefix = -> { "tenant_" }
      assert_equal "tenant_", ApiKeys.configuration.resolved_token_prefix
    end

    test "public key types must be explicitly non-revocable and least privilege" do
      assert_raises(ArgumentError) do
        ApiKeys.configuration.key_types = {
          unsafe: { prefix: "pk", permissions: %w[read], public: true, revocable: true }
        }
      end

      assert_raises(ArgumentError) do
        ApiKeys.configuration.key_types = {
          unsafe: { prefix: "pk", permissions: :all, public: true, revocable: false }
        }
      end
    end

    test "rejects malformed key type definitions" do
      assert_raises(ArgumentError) do
        ApiKeys.configuration.key_types = { unsafe: { prefix: "bad prefix", permissions: %w[read] } }
      end
      assert_raises(ArgumentError) do
        ApiKeys.configuration.key_types = { unsafe: { prefix: "pk", permissions: "read" } }
      end
      assert_raises(ArgumentError) do
        ApiKeys.configuration.key_types = { unsafe: { prefix: "pk", permissions: %w[read], limit: 0 } }
      end
      assert_raises(ArgumentError) do
        ApiKeys.configuration.key_types = {
          unsafe: { prefix: "pk", permissions: Array.new(101) { |index| "scope:#{index}" } }
        }
      end
    end

    test "validates request input configuration" do
      ApiKeys.configuration.header = "X-API-Key"
      ApiKeys.configuration.query_param = "api_key"
      assert_equal "X-API-Key", ApiKeys.configuration.header
      assert_equal "api_key", ApiKeys.configuration.query_param

      ApiKeys.configuration.header = nil
      ApiKeys.configuration.query_param = nil
      assert_nil ApiKeys.configuration.header
      assert_nil ApiKeys.configuration.query_param

      ["bad header", "X\nInjected", Object.new].each do |value|
        assert_raises(ArgumentError) { ApiKeys.configuration.header = value }
      end
      ["bad param", "x[y]", Object.new].each do |value|
        assert_raises(ArgumentError) { ApiKeys.configuration.query_param = value }
      end
    end

    test "validates quotas durations scopes and cache TTL" do
      ApiKeys.configuration.default_max_keys_per_owner = 0
      ApiKeys.configuration.default_max_keys_per_owner = nil
      ApiKeys.configuration.expire_after = 30.days
      ApiKeys.configuration.expire_after = nil
      ApiKeys.configuration.default_scopes = %w[read write read]
      ApiKeys.configuration.cache_ttl = 0
      ApiKeys.configuration.cache_ttl = 5.seconds
      ApiKeys.configuration.cache_ttl = nil
      ApiKeys.configuration.stats_update_interval = 0
      ApiKeys.configuration.stats_update_interval = 5.minutes
      ApiKeys.configuration.stats_update_interval = nil

      assert_equal %w[read write], ApiKeys.configuration.default_scopes
      assert ApiKeys.configuration.default_scopes.frozen?

      [-1, 1.5, "10"].each do |value|
        assert_raises(ArgumentError) { ApiKeys.configuration.default_max_keys_per_owner = value }
      end
      [0.seconds, -1.second, Object.new].each do |value|
        assert_raises(ArgumentError) { ApiKeys.configuration.expire_after = value }
      end
      ["read", ["bad scope"], Array.new(101, "read")].each do |value|
        assert_raises(ArgumentError) { ApiKeys.configuration.default_scopes = value }
      end
      [-1, Float::INFINITY, Float::NAN, "5"].each do |value|
        assert_raises(ArgumentError) { ApiKeys.configuration.cache_ttl = value }
        assert_raises(ArgumentError) { ApiKeys.configuration.stats_update_interval = value }
      end
    end

    test "resolves the configured engine parent controller" do
      custom_parent = Class.new

      ApiKeys.configuration.parent_controller = custom_parent
      assert_same custom_parent, ApiKeys.configuration.parent_controller_class

      ApiKeys.configuration.parent_controller = "ApiKeys::Configuration"
      assert_equal ApiKeys::Configuration, ApiKeys.configuration.parent_controller_class

      [nil, Object.new, "not a constant", "Kernel.system('unsafe')"].each do |value|
        assert_raises(ArgumentError) { ApiKeys.configuration.parent_controller = value }
      end
    end

    test "preserves the legacy engine parent fallback without overriding explicit public configuration" do
      original_engine_parent = ApiKeys::Engine.config.parent_controller
      legacy_parent = Class.new
      explicit_parent = Class.new
      ApiKeys::Engine.config.parent_controller = legacy_parent

      assert_same legacy_parent, ApiKeys.configuration.parent_controller_class

      ApiKeys.configuration.parent_controller = explicit_parent
      assert_same explicit_parent, ApiKeys.configuration.parent_controller_class
    ensure
      ApiKeys::Engine.config.parent_controller = original_engine_parent
    end

    test "validates boolean configuration" do
      ApiKeys::Configuration::BOOLEAN_SETTINGS.each do |setting|
        ApiKeys.configuration.public_send("#{setting}=", true)
        assert_equal true, ApiKeys.configuration.public_send(setting)
        ApiKeys.configuration.public_send("#{setting}=", false)
        assert_equal false, ApiKeys.configuration.public_send(setting)
        assert_raises(ArgumentError) { ApiKeys.configuration.public_send("#{setting}=", "false") }
      end
    end

    test "validates callbacks resolvers comparisons queues and method names" do
      callback = ->(_context) {}
      resolver = ->(key) { key.owner }
      comparator = ->(left, right) { left == right }
      ApiKeys.configuration.before_authentication = callback
      ApiKeys.configuration.after_authentication = callback
      ApiKeys.configuration.tenant_resolver = resolver
      ApiKeys.configuration.secure_compare_proc = comparator
      ApiKeys.configuration.stats_job_queue = :api_keys_stats
      ApiKeys.configuration.callbacks_job_queue = "api_keys_callbacks"
      ApiKeys.configuration.current_owner_method = :current_account
      ApiKeys.configuration.authenticate_owner_method = "authenticate_account!"

      assert_same callback, ApiKeys.configuration.before_authentication
      assert_same resolver, ApiKeys.configuration.tenant_resolver
      assert_same comparator, ApiKeys.configuration.secure_compare_proc

      assert_raises(ArgumentError) { ApiKeys.configuration.before_authentication = Object.new }
      assert_raises(ArgumentError) { ApiKeys.configuration.after_authentication = nil }
      assert_raises(ArgumentError) { ApiKeys.configuration.tenant_resolver = nil }
      assert_raises(ArgumentError) { ApiKeys.configuration.secure_compare_proc = nil }
      assert_raises(ArgumentError) { ApiKeys.configuration.stats_job_queue = "bad queue" }
      assert_raises(ArgumentError) { ApiKeys.configuration.callbacks_job_queue = Object.new }
      assert_raises(ArgumentError) { ApiKeys.configuration.current_owner_method = "bad-method" }
      assert_raises(ArgumentError) { ApiKeys.configuration.authenticate_owner_method = Object.new }

      ApiKeys.configuration.authenticate_owner_method = nil
      assert_nil ApiKeys.configuration.authenticate_owner_method
    end

    test "validates environment and default type selectors" do
      callable = -> { :live }
      ApiKeys.configuration.current_environment = callable
      ApiKeys.configuration.current_environment = :test
      ApiKeys.configuration.current_environment = nil
      ApiKeys.configuration.default_key_type = :secret
      ApiKeys.configuration.default_key_type = nil

      assert_raises(ArgumentError) { ApiKeys.configuration.current_environment = "bad environment" }
      assert_raises(ArgumentError) { ApiKeys.configuration.default_key_type = "bad type" }
    end

    test "configuration hashes are defensive frozen copies" do
      input = {
        publishable: {
          prefix: String.new("pk"),
          permissions: %w[read],
          public: true,
          revocable: false
        }
      }
      ApiKeys.configuration.key_types = input
      input[:publishable][:permissions] << "admin"
      input[:publishable][:prefix].replace("evil")

      assert_equal %w[read], ApiKeys.configuration.key_types[:publishable][:permissions]
      assert_equal "pk", ApiKeys.configuration.key_types[:publishable][:prefix]
      assert_raises(FrozenError) { ApiKeys.configuration.key_types[:publishable][:permissions] << "admin" }

      environments = { test: { prefix_segment: String.new("test") } }
      ApiKeys.configuration.environments = environments
      environments[:test][:prefix_segment].replace("live")
      assert_equal "test", ApiKeys.configuration.environments[:test][:prefix_segment]
      assert ApiKeys.configuration.environments.frozen?
    end

    test "rejects ambiguous normalized names and composite prefixes" do
      assert_raises(ArgumentError) do
        ApiKeys.configuration.key_types = {
          secret: { prefix: "sk", permissions: :all },
          "secret" => { prefix: "other", permissions: :all }
        }
      end

      ApiKeys.configuration.key_types = {
        first: { prefix: "a_b", permissions: %w[read] },
        second: { prefix: "a", permissions: %w[read] }
      }
      assert_raises(ArgumentError) do
        ApiKeys.configuration.environments = {
          short: { prefix_segment: "c" },
          long: { prefix_segment: "b_c" }
        }
      end
    end

    test "rejects malformed environment and key type settings" do
      assert_raises(ArgumentError) { ApiKeys.configuration.environments = [] }
      assert_raises(ArgumentError) { ApiKeys.configuration.environments = { "bad name" => {} } }
      assert_raises(ArgumentError) { ApiKeys.configuration.environments = { test: [] } }
      assert_raises(ArgumentError) { ApiKeys.configuration.environments = { test: { prefix_segment: "bad segment" } } }
      assert_raises(ArgumentError) do
        ApiKeys.configuration.environments = { test: {}, "test" => {} }
      end
      assert_raises(ArgumentError) do
        ApiKeys.configuration.key_types = { secret: { prefix: "sk", permissions: %w[read], revocable: "yes" } }
      end
      assert_raises(ArgumentError) do
        ApiKeys.configuration.key_types = { secret: { prefix: "sk", permissions: ["bad scope"] } }
      end
    end
  end
end
