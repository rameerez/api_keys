# frozen_string_literal: true

require "test_helper"

class KeyTypesTest < ApiKeys::Test
  # =============================================================================
  # Configuration Tests
  # =============================================================================

  test "key_types configuration accepts hash of type definitions" do
    ApiKeys.configure do |config|
      config.key_types = {
        publishable: {
          prefix: "pk",
          permissions: %w[read validate],
          revocable: false,
          limit: 1
        },
        secret: {
          prefix: "sk",
          permissions: :all
        }
      }
    end

    assert_equal 2, ApiKeys.configuration.key_types.keys.length
    assert_includes ApiKeys.configuration.key_types.keys, :publishable
    assert_includes ApiKeys.configuration.key_types.keys, :secret
  end

  test "key_types defaults to empty hash when not configured" do
    # After reset, key_types should default to empty or nil
    assert_respond_to ApiKeys.configuration, :key_types
    assert ApiKeys.configuration.key_types.nil? || ApiKeys.configuration.key_types.empty?
  end

  test "environments configuration accepts hash of environment definitions" do
    ApiKeys.configure do |config|
      config.environments = {
        test: { prefix_segment: "test" },
        live: { prefix_segment: "live" }
      }
    end

    assert_equal 2, ApiKeys.configuration.environments.keys.length
    assert_includes ApiKeys.configuration.environments.keys, :test
    assert_includes ApiKeys.configuration.environments.keys, :live
  end

  test "environments supports sandbox/live naming convention" do
    ApiKeys.configure do |config|
      config.environments = {
        sandbox: { prefix_segment: "test" },
        live: { prefix_segment: "live" }
      }
    end

    assert_includes ApiKeys.configuration.environments.keys, :sandbox
    assert_includes ApiKeys.configuration.environments.keys, :live
  end

  test "environments can have no prefix segment for single-environment setups" do
    ApiKeys.configure do |config|
      config.environments = {
        production: { prefix_segment: nil }
      }
    end

    assert_equal 1, ApiKeys.configuration.environments.keys.length
    assert_nil ApiKeys.configuration.environments[:production][:prefix_segment]
  end

  test "current_environment accepts lambda" do
    ApiKeys.configure do |config|
      config.current_environment = -> { :test }
    end

    assert_respond_to ApiKeys.configuration.current_environment, :call
    assert_equal :test, ApiKeys.configuration.current_environment.call
  end

  test "strict_environment_isolation defaults to false" do
    assert_respond_to ApiKeys.configuration, :strict_environment_isolation
    assert_equal false, ApiKeys.configuration.strict_environment_isolation
  end

  test "strict_environment_isolation can be enabled" do
    ApiKeys.configure do |config|
      config.strict_environment_isolation = true
    end

    assert_equal true, ApiKeys.configuration.strict_environment_isolation
  end

  test "key_types validates unique prefixes" do
    assert_raises(ArgumentError) do
      ApiKeys.configure do |config|
        config.key_types = {
          publishable: { prefix: "pk", permissions: %w[read] },
          public: { prefix: "pk", permissions: %w[read] }  # Same prefix!
        }
      end
    end
  end

  test "key_types allows different prefixes" do
    assert_nothing_raised do
      ApiKeys.configure do |config|
        config.key_types = {
          publishable: { prefix: "pk", permissions: %w[read] },
          secret: { prefix: "sk", permissions: :all }
        }
      end
    end
  end

  # =============================================================================
  # Prefix Building Tests
  # =============================================================================

  test "prefix combines key type and environment" do
    configure_key_types_and_environments!

    user = User.create!(name: "Prefix Test User")
    key = user.create_api_key!(name: "Test Key", key_type: :publishable, environment: :test)

    # Expected prefix: pk_test_
    assert_equal "pk_test_", key.prefix
  end

  test "prefix for secret live key" do
    configure_key_types_and_environments!

    user = User.create!(name: "Prefix Test User")
    key = user.create_api_key!(name: "Test Key", key_type: :secret, environment: :live)

    # Expected prefix: sk_live_
    assert_equal "sk_live_", key.prefix
  end

  test "prefix omits environment segment when nil" do
    ApiKeys.configure do |config|
      config.key_types = {
        api: { prefix: "api", permissions: :all }
      }
      config.environments = {
        default: { prefix_segment: nil }
      }
      config.current_environment = -> { :default }
    end

    user = User.create!(name: "No Env Prefix User")
    key = user.create_api_key!(name: "Test Key", key_type: :api, environment: :default)

    # Expected prefix: api_ (no environment segment)
    assert_equal "api_", key.prefix
  end

  test "token starts with the combined prefix" do
    configure_key_types_and_environments!

    user = User.create!(name: "Token Prefix User")
    key = user.create_api_key!(name: "Test Key", key_type: :publishable, environment: :test)

    assert key.token.start_with?("pk_test_"), "Token should start with pk_test_, got: #{key.token}"
  end

  # =============================================================================
  # Scope Ceiling Tests
  # =============================================================================

  test "key type permissions act as ceiling for scopes" do
    configure_key_types_and_environments!

    user = User.create!(name: "Scope Ceiling User")

    # Publishable keys have permissions: %w[read validate]
    # Trying to create with broader scopes should be limited
    key = user.create_api_key!(
      name: "Limited Key",
      key_type: :publishable,
      environment: :test,
      scopes: %w[read validate issue_license admin]
    )

    # Only allowed scopes should be kept
    assert_includes key.scopes, "read"
    assert_includes key.scopes, "validate"
    refute_includes key.scopes, "issue_license"
    refute_includes key.scopes, "admin"
  end

  test "secret keys with permissions :all can have any scopes" do
    configure_key_types_and_environments!

    user = User.create!(name: "Full Access User")

    key = user.create_api_key!(
      name: "Full Access Key",
      key_type: :secret,
      environment: :live,
      scopes: %w[read validate issue_license admin everything]
    )

    # All scopes should be kept
    assert_equal %w[read validate issue_license admin everything], key.scopes
  end

  test "publishable key validates scope ceiling on create" do
    configure_key_types_and_environments!

    user = User.create!(name: "Validation User")

    # With strict validation, attempting invalid scopes should raise or filter
    key = user.create_api_key!(
      name: "Validated Key",
      key_type: :publishable,
      environment: :test,
      scopes: %w[read issue_license]  # issue_license is not allowed
    )

    # Should only have permitted scope
    assert_equal ["read"], key.scopes
  end

  # =============================================================================
  # Revocable/Non-Revocable Tests
  # =============================================================================

  test "revocable key can be revoked" do
    configure_key_types_and_environments!

    user = User.create!(name: "Revoke Test User")
    key = user.create_api_key!(name: "Secret Key", key_type: :secret, environment: :test)

    # Secret keys are revocable by default
    assert_nothing_raised do
      key.revoke!
    end

    assert key.revoked?
  end

  test "non-revocable key cannot be revoked" do
    configure_key_types_and_environments!

    user = User.create!(name: "Non-Revoke User")
    key = user.create_api_key!(name: "Publishable Key", key_type: :publishable, environment: :test)

    # Publishable keys have revocable: false
    assert_raises(ApiKeys::Errors::KeyNotRevocableError) do
      key.revoke!
    end

    refute key.revoked?
  end

  test "non-revocable key cannot be destroyed" do
    configure_key_types_and_environments!

    user = User.create!(name: "No Destroy User")
    key = user.create_api_key!(name: "Publishable Key", key_type: :publishable, environment: :test)

    assert_raises(ApiKeys::Errors::KeyNotRevocableError) do
      key.destroy!
    end

    # Key should still exist
    assert ApiKeys::ApiKey.exists?(key.id)
  end

  test "revocable? returns false for non-revocable key types" do
    configure_key_types_and_environments!

    user = User.create!(name: "Revocable Check User")
    key = user.create_api_key!(name: "Publishable Key", key_type: :publishable, environment: :test)

    refute key.revocable?
  end

  test "revocable? returns true for revocable key types" do
    configure_key_types_and_environments!

    user = User.create!(name: "Revocable Check User")
    key = user.create_api_key!(name: "Secret Key", key_type: :secret, environment: :test)

    assert key.revocable?
  end

  # =============================================================================
  # Key Limit Tests
  # =============================================================================

  test "enforces key limit per type per environment" do
    configure_key_types_and_environments!

    user = User.create!(name: "Limit Test User")

    # Create first publishable key (limit is 1)
    key1 = user.create_api_key!(name: "Publishable 1", key_type: :publishable, environment: :test)
    assert key1.persisted?

    # Second publishable key for same environment should fail
    assert_raises(ActiveRecord::RecordInvalid) do
      user.create_api_key!(name: "Publishable 2", key_type: :publishable, environment: :test)
    end
  end

  test "key limit is per environment - can have publishable in test and live" do
    configure_key_types_and_environments!

    user = User.create!(name: "Multi-Env User")

    # Create publishable for test environment
    key_test = user.create_api_key!(name: "Publishable Test", key_type: :publishable, environment: :test)
    assert key_test.persisted?

    # Create publishable for live environment - should succeed
    key_live = user.create_api_key!(name: "Publishable Live", key_type: :publishable, environment: :live)
    assert key_live.persisted?
  end

  test "unlimited key type has no limit" do
    configure_key_types_and_environments!

    user = User.create!(name: "Unlimited User")

    # Secret keys have no limit
    5.times do |i|
      key = user.create_api_key!(name: "Secret #{i}", key_type: :secret, environment: :test)
      assert key.persisted?
    end

    assert_equal 5, user.api_keys.where(key_type: "secret").count
  end

  # =============================================================================
  # Environment Isolation Tests
  # =============================================================================

  test "test key returns 403 when strict isolation enabled in production environment" do
    configure_key_types_and_environments!
    ApiKeys.configuration.strict_environment_isolation = true
    ApiKeys.configuration.current_environment = -> { :live }  # We're in "production"

    user = User.create!(name: "Isolation Test User")
    test_key = user.create_api_key!(name: "Test Key", key_type: :secret, environment: :test)

    # Simulate authentication with test key in live environment
    result = authenticate_with_environment_check(test_key.token)

    refute result.success?
    assert_equal :environment_mismatch, result.error_code
  end

  test "live key returns 403 when strict isolation enabled in test environment" do
    configure_key_types_and_environments!
    ApiKeys.configuration.strict_environment_isolation = true
    ApiKeys.configuration.current_environment = -> { :test }  # We're in "test"

    user = User.create!(name: "Isolation Test User")
    live_key = user.create_api_key!(name: "Live Key", key_type: :secret, environment: :live)

    # Simulate authentication with live key in test environment
    result = authenticate_with_environment_check(live_key.token)

    refute result.success?
    assert_equal :environment_mismatch, result.error_code
  end

  test "matching environment passes isolation check" do
    configure_key_types_and_environments!
    ApiKeys.configuration.strict_environment_isolation = true
    ApiKeys.configuration.current_environment = -> { :test }

    user = User.create!(name: "Matching Env User")
    test_key = user.create_api_key!(name: "Test Key", key_type: :secret, environment: :test)

    result = authenticate_with_environment_check(test_key.token)

    assert result.success?
  end

  test "isolation check skipped when strict_environment_isolation is false" do
    configure_key_types_and_environments!
    ApiKeys.configuration.strict_environment_isolation = false
    ApiKeys.configuration.current_environment = -> { :live }

    user = User.create!(name: "No Isolation User")
    test_key = user.create_api_key!(name: "Test Key", key_type: :secret, environment: :test)

    # Should succeed even with mismatched environment
    result = authenticate_with_environment_check(test_key.token)

    assert result.success?
  end

  test "isolation check skipped when current_environment returns nil" do
    configure_key_types_and_environments!
    ApiKeys.configuration.strict_environment_isolation = true
    ApiKeys.configuration.current_environment = -> { nil }  # Returns nil!

    user = User.create!(name: "Nil Env User")
    test_key = user.create_api_key!(name: "Test Key", key_type: :secret, environment: :test)

    # Should pass isolation check since current_environment is nil
    api_key = find_key_by_token(test_key.token)
    result = ApiKeys::Services::Authenticator.send(:check_environment_isolation, api_key, ApiKeys.configuration)

    # Should return nil (check passed) not an error
    assert_nil result
  end

  test "isolation check skipped when current_environment returns empty string" do
    configure_key_types_and_environments!
    ApiKeys.configuration.strict_environment_isolation = true
    ApiKeys.configuration.current_environment = -> { "" }  # Returns empty string!

    user = User.create!(name: "Empty Env User")
    test_key = user.create_api_key!(name: "Test Key", key_type: :secret, environment: :test)

    # Should pass isolation check since current_environment is blank
    api_key = find_key_by_token(test_key.token)
    result = ApiKeys::Services::Authenticator.send(:check_environment_isolation, api_key, ApiKeys.configuration)

    # Should return nil (check passed) not an error
    assert_nil result
  end

  test "isolation check normalizes environments to strings for comparison" do
    configure_key_types_and_environments!
    ApiKeys.configuration.strict_environment_isolation = true
    ApiKeys.configuration.current_environment = -> { :test }  # Returns symbol

    user = User.create!(name: "Symbol Env User")
    test_key = user.create_api_key!(name: "Test Key", key_type: :secret, environment: :test)

    # Environment stored as "test" (string), current returns :test (symbol)
    # They should match after normalization
    api_key = find_key_by_token(test_key.token)
    result = ApiKeys::Services::Authenticator.send(:check_environment_isolation, api_key, ApiKeys.configuration)

    # Should return nil (check passed) - strings match after normalization
    assert_nil result
  end

  test "isolation check correctly rejects mismatched environments after normalization" do
    configure_key_types_and_environments!
    ApiKeys.configuration.strict_environment_isolation = true
    ApiKeys.configuration.current_environment = -> { :live }  # Current is live

    user = User.create!(name: "Mismatch Norm User")
    test_key = user.create_api_key!(name: "Test Key", key_type: :secret, environment: :test)

    # Key is test, current is live - should fail
    api_key = find_key_by_token(test_key.token)
    result = ApiKeys::Services::Authenticator.send(:check_environment_isolation, api_key, ApiKeys.configuration)

    # Should return failure result
    refute_nil result
    assert_equal :environment_mismatch, result.error_code
  end

  # =============================================================================
  # Model Attribute Tests
  # =============================================================================

  test "api_key stores key_type attribute" do
    configure_key_types_and_environments!

    user = User.create!(name: "Attribute Test User")
    key = user.create_api_key!(name: "Test Key", key_type: :publishable, environment: :test)

    assert_equal "publishable", key.key_type
    key.reload
    assert_equal "publishable", key.key_type
  end

  test "api_key stores environment attribute" do
    configure_key_types_and_environments!

    user = User.create!(name: "Attribute Test User")
    key = user.create_api_key!(name: "Test Key", key_type: :publishable, environment: :test)

    assert_equal "test", key.environment
    key.reload
    assert_equal "test", key.environment
  end

  test "api_key scopes by key_type" do
    configure_key_types_and_environments!

    user = User.create!(name: "Scope Query User")
    user.create_api_key!(name: "Publishable", key_type: :publishable, environment: :test)
    user.create_api_key!(name: "Secret 1", key_type: :secret, environment: :test)
    user.create_api_key!(name: "Secret 2", key_type: :secret, environment: :test)

    assert_equal 1, ApiKeys::ApiKey.where(key_type: "publishable").count
    assert_equal 2, ApiKeys::ApiKey.where(key_type: "secret").count
  end

  test "api_key scopes by environment" do
    configure_key_types_and_environments!

    user = User.create!(name: "Env Query User")
    user.create_api_key!(name: "Test Key", key_type: :secret, environment: :test)
    user.create_api_key!(name: "Live Key", key_type: :secret, environment: :live)

    assert_equal 1, ApiKeys::ApiKey.where(environment: "test").count
    assert_equal 1, ApiKeys::ApiKey.where(environment: "live").count
  end

  # =============================================================================
  # Backwards Compatibility Tests
  # =============================================================================

  test "keys work without key_types configured (backwards compatible)" do
    # Don't configure key_types - simulate existing behavior
    user = User.create!(name: "Legacy User")

    # Should work without key_type or environment
    key = user.create_api_key!(name: "Legacy Key")

    assert key.persisted?
    assert_nil key.key_type
    assert_nil key.environment
  end

  test "legacy keys can be revoked" do
    user = User.create!(name: "Legacy Revoke User")
    key = user.create_api_key!(name: "Legacy Key")

    assert_nothing_raised do
      key.revoke!
    end

    assert key.revoked?
  end

  # =============================================================================
  # Validation Tests
  # =============================================================================

  test "validates key_type is defined in configuration" do
    configure_key_types_and_environments!

    user = User.create!(name: "Invalid Type User")

    assert_raises(ArgumentError) do
      user.create_api_key!(name: "Bad Key", key_type: :nonexistent, environment: :test)
    end
  end

  test "validates environment is defined in configuration" do
    configure_key_types_and_environments!

    user = User.create!(name: "Invalid Env User")

    assert_raises(ArgumentError) do
      user.create_api_key!(name: "Bad Key", key_type: :secret, environment: :nonexistent)
    end
  end

  test "requires environment when key_types are configured" do
    configure_key_types_and_environments!

    user = User.create!(name: "Missing Env User")

    # Should use default environment when not specified
    key = user.create_api_key!(name: "Auto Env Key", key_type: :secret)

    # current_environment lambda returns :test by default in our config
    assert_equal "test", key.environment
  end

  # =============================================================================
  # Key Type Info Methods
  # =============================================================================

  test "key_type_config returns the type configuration" do
    configure_key_types_and_environments!

    user = User.create!(name: "Config Info User")
    key = user.create_api_key!(name: "Test Key", key_type: :publishable, environment: :test)

    config = key.key_type_config

    assert_equal "pk", config[:prefix]
    assert_equal %w[read validate], config[:permissions]
    assert_equal false, config[:revocable]
    assert_equal 1, config[:limit]
  end

  test "environment_config returns the environment configuration" do
    configure_key_types_and_environments!

    user = User.create!(name: "Env Info User")
    key = user.create_api_key!(name: "Test Key", key_type: :publishable, environment: :test)

    config = key.environment_config

    assert_equal "test", config[:prefix_segment]
  end

  # =============================================================================
  # Non-Revocable Expiration Tests
  # =============================================================================

  test "non-revocable keys cannot have expiration dates" do
    configure_key_types_and_environments!

    user = User.create!(name: "Non-Revocable Expiry User")

    # Publishable keys have revocable: false
    error = assert_raises(ActiveRecord::RecordInvalid) do
      user.create_api_key!(
        name: "Expiring Publishable",
        key_type: :publishable,
        environment: :test,
        expires_at: 30.days.from_now
      )
    end

    assert_includes error.message, "cannot be set on non-revocable keys"
    assert_includes error.message, "publishable"
  end

  test "revocable keys can have expiration dates" do
    configure_key_types_and_environments!

    user = User.create!(name: "Revocable Expiry User")

    # Secret keys are revocable by default
    key = user.create_api_key!(
      name: "Expiring Secret",
      key_type: :secret,
      environment: :test,
      expires_at: 30.days.from_now
    )

    assert key.persisted?
    assert_not_nil key.expires_at
  end

  test "legacy keys without key_type can have expiration dates" do
    # Don't configure key_types
    user = User.create!(name: "Legacy Expiry User")

    key = user.create_api_key!(
      name: "Expiring Legacy Key",
      expires_at: 30.days.from_now
    )

    assert key.persisted?
    assert_not_nil key.expires_at
  end

  test "non-revocable key expiration error message explains the restriction" do
    configure_key_types_and_environments!

    user = User.create!(name: "Error Message User")
    key = user.api_keys.build(
      name: "Test Key",
      key_type: "publishable",
      environment: "test",
      expires_at: 30.days.from_now
    )

    # Trigger validation
    key.valid?

    error_messages = key.errors[:expires_at]
    assert_not_empty error_messages
    assert error_messages.any? { |msg| msg.include?("non-revocable") }
    assert error_messages.any? { |msg| msg.include?("cannot be revoked or deleted") }
  end

  # =============================================================================
  # Permissions Alias Tests
  # =============================================================================

  test "permissions is an alias for scopes" do
    configure_key_types_and_environments!

    user = User.create!(name: "Permissions Alias User")
    key = user.create_api_key!(
      name: "Test Key",
      key_type: :secret,
      environment: :test,
      scopes: %w[read write admin]
    )

    # permissions should return the same as scopes
    assert_equal key.scopes, key.permissions
    assert_equal %w[read write admin], key.permissions
  end

  test "allows_permission? works like allows_scope?" do
    configure_key_types_and_environments!

    user = User.create!(name: "Permissions Check User")
    key = user.create_api_key!(
      name: "Test Key",
      key_type: :secret,
      environment: :test,
      scopes: %w[read write]
    )

    assert key.allows_permission?("read")
    assert key.allows_permission?("write")
    refute key.allows_permission?("admin")
  end

  # =============================================================================
  # Default Key Type Tests
  # =============================================================================

  test "default_key_type configuration option exists" do
    assert_respond_to ApiKeys.configuration, :default_key_type
  end

  test "default_key_type defaults to nil" do
    assert_nil ApiKeys.configuration.default_key_type
  end

  test "default_key_type is used when key_type not specified" do
    configure_key_types_and_environments!
    ApiKeys.configuration.default_key_type = :secret

    user = User.create!(name: "Default Type User")
    key = user.create_api_key!(name: "Auto Type Key")

    assert_equal "secret", key.key_type
    assert key.token.start_with?("sk_test_")
  end

  test "explicit key_type overrides default_key_type" do
    configure_key_types_and_environments!
    ApiKeys.configuration.default_key_type = :secret

    user = User.create!(name: "Override Type User")
    key = user.create_api_key!(name: "Explicit Type Key", key_type: :publishable)

    assert_equal "publishable", key.key_type
    assert key.token.start_with?("pk_test_")
  end

  # =============================================================================
  # Dashboard Environment Filtering Tests
  # =============================================================================

  test "dashboard_allow_cross_environment configuration option exists" do
    assert_respond_to ApiKeys.configuration, :dashboard_allow_cross_environment
  end

  test "dashboard_allow_cross_environment defaults to false" do
    assert_equal false, ApiKeys.configuration.dashboard_allow_cross_environment
  end

  test "dashboard_allow_cross_environment can be set to true" do
    ApiKeys.configure do |config|
      config.dashboard_allow_cross_environment = true
    end

    assert_equal true, ApiKeys.configuration.dashboard_allow_cross_environment
  end

  # =============================================================================
  # Public Key Token Storage Tests
  # =============================================================================

  test "public_key_type? returns true for public non-revocable keys" do
    configure_key_types_with_public!

    user = User.create!(name: "Public Key User")
    key = user.create_api_key!(name: "Publishable Key", key_type: :publishable, environment: :test)

    assert key.public_key_type?
  end

  test "public_key_type? returns false for secret keys" do
    configure_key_types_with_public!

    user = User.create!(name: "Secret Key User")
    key = user.create_api_key!(name: "Secret Key", key_type: :secret, environment: :test)

    refute key.public_key_type?
  end

  test "public_key_type? returns false for keys without key_type" do
    # Legacy key without key types configured
    user = User.create!(name: "Legacy User")
    key = user.create_api_key!(name: "Legacy Key")

    refute key.public_key_type?
  end

  test "public_key_type? returns false when public is true but revocable is true" do
    ApiKeys.configure do |config|
      config.key_types = {
        weird: {
          prefix: "wk",
          permissions: %w[read],
          revocable: true,  # revocable
          public: true      # but public
        }
      }
      config.environments = { test: { prefix_segment: "test" } }
      config.current_environment = -> { :test }
    end

    user = User.create!(name: "Weird Key User")
    key = user.create_api_key!(name: "Weird Key", key_type: :weird, environment: :test)

    # Should be false because revocable is true
    refute key.public_key_type?
  end

  test "viewable_token returns stored token for public keys" do
    configure_key_types_with_public!

    user = User.create!(name: "Viewable Token User")
    key = user.create_api_key!(name: "Publishable Key", key_type: :publishable, environment: :test)

    # Capture the token at creation time
    original_token = key.token

    # Reload and check viewable_token
    key.reload
    assert_equal original_token, key.viewable_token
  end

  test "viewable_token returns nil for secret keys" do
    configure_key_types_with_public!

    user = User.create!(name: "Secret Token User")
    key = user.create_api_key!(name: "Secret Key", key_type: :secret, environment: :test)

    key.reload
    assert_nil key.viewable_token
  end

  test "viewable_token returns nil for legacy keys" do
    user = User.create!(name: "Legacy Token User")
    key = user.create_api_key!(name: "Legacy Key")

    key.reload
    assert_nil key.viewable_token
  end

  test "public key stores token in metadata" do
    configure_key_types_with_public!

    user = User.create!(name: "Metadata Token User")
    key = user.create_api_key!(name: "Publishable Key", key_type: :publishable, environment: :test)

    original_token = key.token
    key.reload

    # Token should be stored in metadata
    assert_equal original_token, key.metadata["token"]
  end

  test "secret key does NOT store token in metadata" do
    configure_key_types_with_public!

    user = User.create!(name: "No Store User")
    key = user.create_api_key!(name: "Secret Key", key_type: :secret, environment: :test)

    key.reload

    # Token should NOT be in metadata
    assert_nil key.metadata["token"]
  end

  test "public key token can be retrieved after reload" do
    configure_key_types_with_public!

    user = User.create!(name: "Persistent Token User")
    key = user.create_api_key!(name: "Publishable Key", key_type: :publishable, environment: :test)

    original_token = key.token

    # Simulate a fresh load from database
    loaded_key = ApiKeys::ApiKey.find(key.id)

    assert_equal original_token, loaded_key.viewable_token
    assert loaded_key.viewable_token.start_with?("pk_test_")
  end

  test "public key without public config option does not store token" do
    # Configure without public: true
    configure_key_types_and_environments!  # Uses the standard config without public option

    user = User.create!(name: "No Public Config User")
    key = user.create_api_key!(name: "Publishable Key", key_type: :publishable, environment: :test)

    key.reload

    # Token should NOT be stored since public: true is not set
    assert_nil key.metadata["token"]
    assert_nil key.viewable_token
  end

  # =============================================================================
  # SECURITY: Secret Key Protection Tests
  # These tests verify that secret keys are NEVER stored or revealed
  # =============================================================================

  test "SECURITY: secret key token is NEVER stored in metadata even with public config" do
    configure_key_types_with_public!

    user = User.create!(name: "Secret Safety User")
    key = user.create_api_key!(name: "Secret Key", key_type: :secret, environment: :test)
    original_token = key.token

    key.reload

    # CRITICAL: Token must NOT be in metadata
    assert_nil key.metadata["token"], "SECRET KEY TOKEN WAS STORED IN METADATA - SECURITY VIOLATION!"

    # CRITICAL: viewable_token must return nil
    assert_nil key.viewable_token, "SECRET KEY TOKEN WAS REVEALED - SECURITY VIOLATION!"

    # Verify the key still works (token was generated correctly)
    assert original_token.start_with?("sk_test_")
  end

  test "SECURITY: secret key token is NEVER revealed via viewable_token" do
    configure_key_types_with_public!

    user = User.create!(name: "Viewable Safety User")
    key = user.create_api_key!(name: "Secret Key", key_type: :secret, environment: :live)

    # Even for live environment secret keys
    key.reload
    assert_nil key.viewable_token, "SECRET KEY TOKEN WAS REVEALED - SECURITY VIOLATION!"
  end

  test "SECURITY: revocable keys with public:true do NOT store token" do
    # This is a critical edge case - someone might misconfigure public:true on a revocable key
    ApiKeys.configure do |config|
      config.key_types = {
        misconfigured: {
          prefix: "mc",
          permissions: :all,
          revocable: true,   # Revocable!
          public: true       # But marked as public - should be ignored!
        }
      }
      config.environments = { test: { prefix_segment: "test" } }
      config.current_environment = -> { :test }
    end

    user = User.create!(name: "Misconfigured Key User")
    key = user.create_api_key!(name: "Misconfigured Key", key_type: :misconfigured, environment: :test)

    key.reload

    # Even though public:true is set, revocable:true should prevent storage
    assert_nil key.metadata["token"], "REVOCABLE KEY TOKEN WAS STORED - SECURITY VIOLATION!"
    assert_nil key.viewable_token, "REVOCABLE KEY TOKEN WAS REVEALED - SECURITY VIOLATION!"
  end

  test "SECURITY: legacy keys without key_type NEVER store token" do
    # Legacy keys (no key_types configured) should never store tokens
    user = User.create!(name: "Legacy Safety User")
    key = user.create_api_key!(name: "Legacy Key")

    key.reload

    assert_nil key.metadata["token"], "LEGACY KEY TOKEN WAS STORED - SECURITY VIOLATION!"
    assert_nil key.viewable_token, "LEGACY KEY TOKEN WAS REVEALED - SECURITY VIOLATION!"
  end

  test "SECURITY: key with nil key_type NEVER stores token" do
    configure_key_types_with_public!

    # Create a key directly without going through create_api_key! to test edge case
    user = User.create!(name: "Nil Type User")

    # Use build to bypass some validations, simulating edge case
    key = ApiKeys::ApiKey.new(
      owner: user,
      name: "Nil Type Key",
      key_type: nil,  # Explicitly nil
      environment: nil
    )
    key.save!

    key.reload

    assert_nil key.metadata["token"], "NIL KEY_TYPE KEY TOKEN WAS STORED - SECURITY VIOLATION!"
    assert_nil key.viewable_token, "NIL KEY_TYPE KEY TOKEN WAS REVEALED - SECURITY VIOLATION!"
  end

  test "SECURITY: key with empty string key_type NEVER stores token" do
    user = User.create!(name: "Empty Type User")

    key = ApiKeys::ApiKey.new(
      owner: user,
      name: "Empty Type Key",
      key_type: "",  # Empty string
      environment: ""
    )
    key.save!

    key.reload

    assert_nil key.metadata["token"], "EMPTY KEY_TYPE KEY TOKEN WAS STORED - SECURITY VIOLATION!"
    assert_nil key.viewable_token, "EMPTY KEY_TYPE KEY TOKEN WAS REVEALED - SECURITY VIOLATION!"
  end

  test "SECURITY: metadata does not contain token for ANY secret key type" do
    # Configure multiple secret key types
    ApiKeys.configure do |config|
      config.key_types = {
        publishable: { prefix: "pk", permissions: %w[read], revocable: false, public: true },
        secret: { prefix: "sk", permissions: :all },
        admin: { prefix: "ak", permissions: :all },  # Another full-access key
        service: { prefix: "sv", permissions: :all } # Service account key
      }
      config.environments = { test: { prefix_segment: "test" } }
      config.current_environment = -> { :test }
    end

    user = User.create!(name: "Multi Secret User")

    # Create all non-public key types
    secret_key = user.create_api_key!(name: "Secret", key_type: :secret, environment: :test)
    admin_key = user.create_api_key!(name: "Admin", key_type: :admin, environment: :test)
    service_key = user.create_api_key!(name: "Service", key_type: :service, environment: :test)

    [secret_key, admin_key, service_key].each do |key|
      key.reload
      assert_nil key.metadata["token"], "#{key.key_type.upcase} KEY TOKEN WAS STORED - SECURITY VIOLATION!"
      assert_nil key.viewable_token, "#{key.key_type.upcase} KEY TOKEN WAS REVEALED - SECURITY VIOLATION!"
      refute key.public_key_type?, "#{key.key_type.upcase} KEY WAS MARKED AS PUBLIC - SECURITY VIOLATION!"
    end
  end

  test "SECURITY: only publishable keys with public:true AND revocable:false store token" do
    configure_key_types_with_public!

    user = User.create!(name: "Only Public User")

    # Create both key types
    publishable = user.create_api_key!(name: "Publishable", key_type: :publishable, environment: :test)
    secret = user.create_api_key!(name: "Secret", key_type: :secret, environment: :test)

    publishable_token = publishable.token
    secret_token = secret.token

    publishable.reload
    secret.reload

    # Only publishable should have stored token
    assert_equal publishable_token, publishable.metadata["token"], "Publishable key should store token"
    assert_equal publishable_token, publishable.viewable_token, "Publishable key should reveal token"

    # Secret must NOT have stored token
    assert_nil secret.metadata["token"], "SECRET KEY TOKEN WAS STORED - SECURITY VIOLATION!"
    assert_nil secret.viewable_token, "SECRET KEY TOKEN WAS REVEALED - SECURITY VIOLATION!"
  end

  test "SECURITY: public_key_type? requires BOTH public:true AND revocable:false" do
    # Test all combinations
    test_cases = [
      { public: true, revocable: false, expected: true, desc: "public:true, revocable:false" },
      { public: true, revocable: true, expected: false, desc: "public:true, revocable:true" },
      { public: false, revocable: false, expected: false, desc: "public:false, revocable:false" },
      { public: false, revocable: true, expected: false, desc: "public:false, revocable:true" },
      { public: nil, revocable: false, expected: false, desc: "public:nil, revocable:false" },
      { public: nil, revocable: true, expected: false, desc: "public:nil, revocable:true" },
    ]

    test_cases.each_with_index do |tc, idx|
      ApiKeys.configure do |config|
        config.key_types = {
          testkey: {
            prefix: "t#{idx}",
            permissions: %w[read],
            revocable: tc[:revocable],
            public: tc[:public]
          }.compact  # Remove nil values
        }
        config.environments = { test: { prefix_segment: "test" } }
        config.current_environment = -> { :test }
      end

      user = User.create!(name: "Combo Test User #{idx}")
      key = user.create_api_key!(name: "Test Key", key_type: :testkey, environment: :test)

      if tc[:expected]
        assert key.public_key_type?, "Expected public_key_type? to be true for #{tc[:desc]}"
        assert_not_nil key.metadata["token"], "Expected token to be stored for #{tc[:desc]}"
      else
        refute key.public_key_type?, "Expected public_key_type? to be false for #{tc[:desc]} - SECURITY VIOLATION!"
        assert_nil key.metadata["token"], "Token should NOT be stored for #{tc[:desc]} - SECURITY VIOLATION!"
      end
    end
  end

  # =============================================================================
  # Migration Required Error Tests
  # =============================================================================

  test "MigrationRequiredError class exists" do
    assert_kind_of Class, ApiKeys::Errors::MigrationRequiredError
  end

  test "MigrationRequiredError includes helpful message" do
    error = ApiKeys::Errors::MigrationRequiredError.new(missing_columns: %w[key_type environment])

    assert_includes error.message, "key_type"
    assert_includes error.message, "environment"
    assert_includes error.message, "rails generate api_keys:add_key_types"
    assert_includes error.message, "rails db:migrate"
  end

  private

  def configure_key_types_and_environments!
    ApiKeys.configure do |config|
      config.key_types = {
        publishable: {
          prefix: "pk",
          permissions: %w[read validate],
          revocable: false,
          limit: 1
        },
        secret: {
          prefix: "sk",
          permissions: :all
          # revocable defaults to true, limit defaults to nil (unlimited)
        }
      }

      config.environments = {
        test: { prefix_segment: "test" },
        live: { prefix_segment: "live" }
      }

      config.current_environment = -> { :test }
      config.strict_environment_isolation = false
    end
  end

  def configure_key_types_with_public!
    ApiKeys.configure do |config|
      config.key_types = {
        publishable: {
          prefix: "pk",
          permissions: %w[read validate],
          revocable: false,
          public: true,  # Store plaintext token for viewing
          limit: 1
        },
        secret: {
          prefix: "sk",
          permissions: :all
          # revocable defaults to true
          # public defaults to false (never store secret keys!)
        }
      }

      config.environments = {
        test: { prefix_segment: "test" },
        live: { prefix_segment: "live" }
      }

      config.current_environment = -> { :test }
      config.strict_environment_isolation = false
    end
  end

  def authenticate_with_environment_check(token)
    # Find the key first
    api_key = find_key_by_token(token)
    return ApiKeys::Services::Authenticator::Result.failure(
      error_code: :invalid_token,
      message: "API token is invalid"
    ) unless api_key

    # Check environment isolation
    if ApiKeys.configuration.strict_environment_isolation
      current_env = ApiKeys.configuration.current_environment.call.to_s
      key_env = api_key.environment.to_s

      if current_env != key_env
        return ApiKeys::Services::Authenticator::Result.failure(
          error_code: :environment_mismatch,
          message: "API key environment (#{key_env}) does not match current environment (#{current_env})"
        )
      end
    end

    # Check other conditions
    if api_key.revoked?
      return ApiKeys::Services::Authenticator::Result.failure(
        error_code: :revoked_key,
        message: "API key has been revoked"
      )
    end

    if api_key.expired?
      return ApiKeys::Services::Authenticator::Result.failure(
        error_code: :expired_key,
        message: "API key has expired"
      )
    end

    ApiKeys::Services::Authenticator::Result.success(api_key)
  end

  def find_key_by_token(token)
    # Simple SHA256 lookup for tests
    token_digest = Digest::SHA256.hexdigest(token)
    ApiKeys::ApiKey.find_by(token_digest: token_digest, digest_algorithm: "sha256")
  end
end
