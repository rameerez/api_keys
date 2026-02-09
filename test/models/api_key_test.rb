# frozen_string_literal: true

require "test_helper"

module ApiKeys
  module Models
    class ApiKeyTest < ApiKeys::Test
      def setup
        super # Ensure base setup (config reset, DB clear) runs
        @user = User.create!(name: "Test User")
      end

      # === Creation & Defaults ===

      test "should create an api key with defaults" do
        api_key = ApiKeys::ApiKey.create!(owner: @user, name: "Default Key")
        assert api_key.persisted?
        assert_not_nil api_key.token
        assert api_key.token.start_with?(ApiKeys.configuration.token_prefix.call)
        assert_not_nil api_key.token_digest
        assert_equal ApiKeys.configuration.hash_strategy.to_s, api_key.digest_algorithm
        assert_equal ApiKeys.configuration.default_scopes, api_key.scopes
        assert_equal ({}), api_key.metadata
        assert_nil api_key.expires_at
        assert_nil api_key.last_used_at
        assert_equal 0, api_key.requests_count
        assert_nil api_key.revoked_at
        assert api_key.active?
      end

      test "token is only available immediately after create" do
        api_key = ApiKeys::ApiKey.create!(owner: @user, name: "Mask Test")
        token = api_key.token
        assert_not_nil token

        # Reload the record
        reloaded_key = ApiKeys::ApiKey.find(api_key.id)
        assert_nil reloaded_key.token
      end

      test "allows_scope? checks correctly" do
        api_key = ApiKeys::ApiKey.create!(owner: @user, name: "Scope Test", scopes: %w[read write])
        assert api_key.allows_scope?("read")
        assert api_key.allows_scope?(:write)
        assert_not api_key.allows_scope?("admin")
      end

      test "allows_scope? with blank scopes in simple mode allows all" do
        # In simple mode (no key_types configured), blank scopes = unrestricted
        api_key = ApiKeys::ApiKey.create!(owner: @user, name: "No Scopes", scopes: [])
        assert api_key.allows_scope?("read")
        assert api_key.allows_scope?("admin")
        assert api_key.allows_scope?("anything")
      end

      test "allows_scope? with blank scopes in key_types mode denies all" do
        # In key_types mode, blank scopes = no permissions
        original_key_types = ApiKeys.configuration.key_types
        ApiKeys.configuration.key_types = {
          publishable: { prefix: "pk", permissions: %w[read] },
          secret: { prefix: "sk", permissions: :all }
        }

        api_key = ApiKeys::ApiKey.create!(owner: @user, name: "Empty Scopes", scopes: [])
        assert_not api_key.allows_scope?("read")
        assert_not api_key.allows_scope?("admin")
      ensure
        ApiKeys.configuration.key_types = original_key_types
      end

      test "creates with sha256 digest by default" do
        api_key = ApiKeys::ApiKey.create!(owner: @user, name: "SHA256 Default")
        assert_equal "sha256", api_key.digest_algorithm
        assert ApiKeys::Services::Digestor.match?(token: api_key.instance_variable_get(:@token), stored_digest: api_key.token_digest, strategy: :sha256)
      end

      test "creates with sha256 digest if configured" do
        with_hash_strategy(:sha256) do
          api_key = ApiKeys::ApiKey.create!(owner: @user, name: "SHA256 Key")
          assert_equal "sha256", api_key.digest_algorithm
          assert ApiKeys::Services::Digestor.match?(token: api_key.instance_variable_get(:@token), stored_digest: api_key.token_digest, strategy: :sha256)
        end
      end

      # === Bcrypt strategy ===
      test "creates with bcrypt digest if configured" do
        with_hash_strategy(:bcrypt) do
          api_key = ApiKeys::ApiKey.create!(owner: @user, name: "BCrypt Key")
          assert_equal "bcrypt", api_key.digest_algorithm
          assert BCrypt::Password.valid_hash?(api_key.token_digest)
          assert BCrypt::Password.new(api_key.token_digest) == api_key.instance_variable_get(:@token)
        end
      end

      test "bcrypt digest format and length look valid" do
        with_hash_strategy(:bcrypt) do
          api_key = ApiKeys::ApiKey.create!(owner: @user, name: "BCrypt Format Key")
          digest = api_key.token_digest
          # Typical bcrypt hashes look like: $2a$12$... or $2b$...
          assert_match(/^\$2[aby]\$\d{2}\$/ , digest)
          assert_operator digest.length, :>=, 55 # common bcrypt length ~60
        end
      end

      test "masked_token and last4 correct under bcrypt" do
        with_hash_strategy(:bcrypt) do
          api_key = ApiKeys::ApiKey.create!(owner: @user, name: "BCrypt Masked")
          token = api_key.instance_variable_get(:@token)
          random_part = token.delete_prefix(api_key.prefix)
          expected_last4 = random_part.last(4)

          assert_equal expected_last4, api_key.last4
          assert_equal "#{api_key.prefix}••••#{api_key.last4}", api_key.masked_token
        end
      end

      test ".active scope works" do
        active_key = ApiKeys::ApiKey.create!(owner: @user, name: "Active")
        revoked_key = ApiKeys::ApiKey.create!(owner: @user, name: "Revoked").tap(&:revoke!)
        expired_key = ApiKeys::ApiKey.create!(owner: @user, name: "Expired").tap { |k| k.update_column(:expires_at, 1.day.ago) }

        active_keys = ApiKeys::ApiKey.active.to_a
        assert_includes active_keys, active_key
        assert_not_includes active_keys, revoked_key
        assert_not_includes active_keys, expired_key
      end

      test ".revoked scope works" do
        active_key = ApiKeys::ApiKey.create!(owner: @user, name: "Active")
        revoked_key = ApiKeys::ApiKey.create!(owner: @user, name: "Revoked").tap(&:revoke!)

        revoked_keys = ApiKeys::ApiKey.revoked.to_a
        assert_includes revoked_keys, revoked_key
        assert_not_includes revoked_keys, active_key
      end

      test ".expired scope works" do
        active_key = ApiKeys::ApiKey.create!(owner: @user, name: "Active")
        expired_key = ApiKeys::ApiKey.create!(owner: @user, name: "Expired").tap { |k| k.update_column(:expires_at, 1.day.ago) }

        expired_keys = ApiKeys::ApiKey.expired.to_a
        assert_includes expired_keys, expired_key
        assert_not_includes expired_keys, active_key
      end

      # === Usage Analytics Scopes ===
      # These scopes help admin dashboards analyze API key usage patterns

      test ".never_used scope returns keys that have never been used" do
        used_key = ApiKeys::ApiKey.create!(owner: @user, name: "Used")
        used_key.update_column(:last_used_at, 1.day.ago)

        never_used_key = ApiKeys::ApiKey.create!(owner: @user, name: "Never Used")
        # last_used_at is nil by default

        never_used_keys = ApiKeys::ApiKey.never_used.to_a
        assert_includes never_used_keys, never_used_key
        assert_not_includes never_used_keys, used_key
      end

      test ".used scope returns keys that have been used at least once" do
        used_key = ApiKeys::ApiKey.create!(owner: @user, name: "Used")
        used_key.update_column(:last_used_at, 1.day.ago)

        never_used_key = ApiKeys::ApiKey.create!(owner: @user, name: "Never Used")

        used_keys = ApiKeys::ApiKey.used.to_a
        assert_includes used_keys, used_key
        assert_not_includes used_keys, never_used_key
      end

      test ".by_requests scope orders by requests_count descending" do
        low_usage = ApiKeys::ApiKey.create!(owner: @user, name: "Low")
        low_usage.update_column(:requests_count, 10)

        high_usage = ApiKeys::ApiKey.create!(owner: @user, name: "High")
        high_usage.update_column(:requests_count, 1000)

        medium_usage = ApiKeys::ApiKey.create!(owner: @user, name: "Medium")
        medium_usage.update_column(:requests_count, 100)

        ordered = ApiKeys::ApiKey.by_requests.to_a
        assert_equal [high_usage, medium_usage, low_usage], ordered
      end

      test ".by_last_used scope orders by last_used_at descending with nulls last" do
        old_key = ApiKeys::ApiKey.create!(owner: @user, name: "Old")
        old_key.update_column(:last_used_at, 7.days.ago)

        recent_key = ApiKeys::ApiKey.create!(owner: @user, name: "Recent")
        recent_key.update_column(:last_used_at, 1.hour.ago)

        never_used_key = ApiKeys::ApiKey.create!(owner: @user, name: "Never")
        # last_used_at is nil

        ordered = ApiKeys::ApiKey.by_last_used.to_a
        # Recent should come first, then old, then never used (nulls last)
        assert_equal recent_key, ordered.first
        assert_equal old_key, ordered.second
        assert_equal never_used_key, ordered.last
      end

      test ".stale scope returns active keys not used in specified period" do
        # Active key used recently - should NOT be stale
        recent_key = ApiKeys::ApiKey.create!(owner: @user, name: "Recent")
        recent_key.update_column(:last_used_at, 5.days.ago)

        # Active key not used in 30+ days - should be stale
        stale_key = ApiKeys::ApiKey.create!(owner: @user, name: "Stale")
        stale_key.update_column(:last_used_at, 45.days.ago)

        # Active key never used - should be stale
        never_used_key = ApiKeys::ApiKey.create!(owner: @user, name: "Never Used")

        # Revoked key not used in 30+ days - should NOT be stale (already inactive)
        revoked_key = ApiKeys::ApiKey.create!(owner: @user, name: "Revoked")
        revoked_key.update_column(:last_used_at, 60.days.ago)
        revoked_key.revoke!

        stale_keys = ApiKeys::ApiKey.stale(30.days).to_a
        assert_includes stale_keys, stale_key
        assert_includes stale_keys, never_used_key
        assert_not_includes stale_keys, recent_key
        assert_not_includes stale_keys, revoked_key
      end

      test ".stale scope defaults to 30 days" do
        stale_key = ApiKeys::ApiKey.create!(owner: @user, name: "Stale")
        stale_key.update_column(:last_used_at, 31.days.ago)

        recent_key = ApiKeys::ApiKey.create!(owner: @user, name: "Recent")
        recent_key.update_column(:last_used_at, 29.days.ago)

        stale_keys = ApiKeys::ApiKey.stale.to_a
        assert_includes stale_keys, stale_key
        assert_not_includes stale_keys, recent_key
      end

      test ".most_used is an alias for .by_requests" do
        low_usage = ApiKeys::ApiKey.create!(owner: @user, name: "Low")
        low_usage.update_column(:requests_count, 10)

        high_usage = ApiKeys::ApiKey.create!(owner: @user, name: "High")
        high_usage.update_column(:requests_count, 1000)

        assert_equal ApiKeys::ApiKey.by_requests.to_a, ApiKeys::ApiKey.most_used.to_a
      end

      test ".recently_used is an alias for .by_last_used" do
        old_key = ApiKeys::ApiKey.create!(owner: @user, name: "Old")
        old_key.update_column(:last_used_at, 7.days.ago)

        recent_key = ApiKeys::ApiKey.create!(owner: @user, name: "Recent")
        recent_key.update_column(:last_used_at, 1.hour.ago)

        assert_equal ApiKeys::ApiKey.by_last_used.to_a, ApiKeys::ApiKey.recently_used.to_a
      end

      test ".inactive_for_30_days scope is equivalent to .stale with 30 days" do
        stale_key = ApiKeys::ApiKey.create!(owner: @user, name: "Stale")
        stale_key.update_column(:last_used_at, 31.days.ago)

        recent_key = ApiKeys::ApiKey.create!(owner: @user, name: "Recent")
        recent_key.update_column(:last_used_at, 29.days.ago)

        assert_equal ApiKeys::ApiKey.stale(30.days).to_a, ApiKeys::ApiKey.inactive_for_30_days.to_a
        assert_includes ApiKeys::ApiKey.inactive_for_30_days.to_a, stale_key
        assert_not_includes ApiKeys::ApiKey.inactive_for_30_days.to_a, recent_key
      end

      test "revoke! sets revoked_at timestamp" do
        api_key = ApiKeys::ApiKey.create!(owner: @user, name: "To Revoke")
        assert_nil api_key.revoked_at
        freeze_time do
          api_key.revoke!
          assert_equal Time.current, api_key.revoked_at
        end
        assert api_key.revoked?
        assert_not api_key.active?
      end

      test "expired? and active? check expiry date" do
        future_key = ApiKeys::ApiKey.create!(owner: @user, name: "Future", expires_at: 1.day.from_now)
        past_key = ApiKeys::ApiKey.create!(owner: @user, name: "Past").tap { |k| k.update_column(:expires_at, 1.day.ago) }
        nil_key = ApiKeys::ApiKey.create!(owner: @user, name: "Nil")

        assert_not future_key.expired?
        assert future_key.active?
        assert past_key.expired?
        assert_not past_key.active?
        assert_not nil_key.expired?
        assert nil_key.active?
      end

      test "token digest should be unique" do
        key1 = ApiKeys::ApiKey.create!(owner: @user, name: "Key 1")
        key2 = ApiKeys::ApiKey.new(owner: @user, name: "Key 2")

        # Manually set digest to simulate collision (highly unlikely in practice)
        key2.send(:generate_token_and_digest) # Generate a token normally
        key2.token_digest = key1.token_digest # Force collision

        assert_not key2.valid?
        assert_includes key2.errors[:token_digest], "has already been taken"
      end

      test "should require name if owner configured" do
        @user.class.api_keys_settings = @user.class.api_keys_settings.merge(require_name: true)
        api_key = ApiKeys::ApiKey.new(owner: @user)
        assert_not api_key.valid?
        assert_includes api_key.errors[:name], "can't be blank"
      ensure
        # Reset to avoid affecting other tests
        @user.class.api_keys_settings = @user.class.api_keys_settings.merge(require_name: false)
      end

      test "should require name if globally configured" do
        ApiKeys.configuration.require_key_name = true
        api_key = ApiKeys::ApiKey.new # no owner, global config applies
        assert_not api_key.valid?
        assert_includes api_key.errors[:name], "can't be blank"
      ensure
        ApiKeys.configuration.require_key_name = false
      end

      test "should validate max_keys quota if owner configured" do
        @user.class.api_keys_settings = @user.class.api_keys_settings.merge(max_keys: 1)
        first_key = ApiKeys::ApiKey.create!(owner: @user, name: "Key 1") # First key is fine

        api_key2 = ApiKeys::ApiKey.new(owner: @user, name: "Key 2")
        assert_not api_key2.valid?
        assert_includes api_key2.errors[:base], "exceeds maximum allowed API keys (1) for this owner"

        # Revoked keys should not count towards quota: revoke the existing key
        first_key.revoke!
        api_key3 = ApiKeys::ApiKey.new(owner: @user, name: "Active Key")
        assert api_key3.valid?, "Revoked key should not count towards quota. Errors: #{api_key3.errors.full_messages}"
      ensure
        @user.class.api_keys_settings = @user.class.api_keys_settings.merge(max_keys: nil)
      end

      test "expiration date cannot be in the past" do
        api_key = ApiKeys::ApiKey.new(owner: @user, name: "Past Expiry", expires_at: 1.minute.ago)
        assert_not api_key.valid?
        assert_includes api_key.errors[:expires_at], "can't be in the past"
      end

      # TODO: Add test for global max_keys config
      # TODO: Add test for default_scopes from owner config
      # TODO: Add test for prefix generation (e.g., different envs)
      # TODO: Add test for metadata storage/retrieval
      # TODO: Add test for last_used_at update (requires mocking request/auth)
      # TODO: Add test for requests_count update (requires mocking request/auth)
    end
  end
end
