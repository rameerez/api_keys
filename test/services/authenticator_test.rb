# frozen_string_literal: true

require "test_helper"
require "ostruct"

module ApiKeys
  module Services
    class AuthenticatorTest < ApiKeys::Test
      # Simple fake cache that supports read/write without strict expectations
      class FakeCache
        attr_reader :recorded_reads, :recorded_writes
        def initialize(read_map = {})
          @read_map = read_map
          @recorded_reads = []
          @recorded_writes = []
        end
        def read(key)
          @recorded_reads << key
          @read_map.fetch(key, nil)
        end
        def write(*args)
          @recorded_writes << args
          @read_map[args.first] = args[1]
          true
        end

        def delete(key)
          @read_map.delete(key)
        end
      end

      class FailingCache
        def read(*)
          raise IOError, "cache unavailable"
        end

        def write(*)
          raise IOError, "cache unavailable"
        end
      end

      def setup
        super
        @user = User.create!(name: "Auth User")
        @api_key = ApiKeys::ApiKey.create!(owner: @user, name: "Auth Key")
        @token = @api_key.token # Grab the plaintext token after creation
        # Ensure the key is reloaded to clear the plaintext token reader
        @api_key = ApiKeys::ApiKey.find(@api_key.id)
        assert_nil @api_key.token # Verify plaintext token is gone
      end

      # === Helper Methods ===

      def mock_request(headers: {}, query_params: {}, protocol: "https://")
        # Simple mock request object responding to headers and query_parameters
        OpenStruct.new(
          headers: headers,
          query_parameters: query_params,
          protocol: protocol,
          uuid: SecureRandom.uuid
        )
      end

      def mock_cache(read_map = {})
        @mock_cache = FakeCache.new(read_map)
        Rails.stubs(:cache).returns(@mock_cache)
        @mock_cache
      end

      # === Test Cases ===

      test "authenticates successfully with valid token in Authorization header" do
        request = mock_request(headers: { "Authorization" => "Bearer #{@token}" })
        mock_cache # default (all reads miss)

        result = ApiKeys::Services::Authenticator.call(request)

        assert result.success?
        assert_equal @api_key, result.api_key
        assert_nil result.error_code
      end

      test "authenticates successfully with bcrypt strategy" do
        with_hash_strategy(:bcrypt) do
          key = ApiKeys::ApiKey.create!(owner: @user, name: "BCrypt Auth Key")
          token = key.token
          key = ApiKeys::ApiKey.find(key.id)

          request = mock_request(headers: { "Authorization" => "Bearer #{token}" })
          mock_cache

          result = ApiKeys::Services::Authenticator.call(request)
          assert result.success?
          assert_equal key, result.api_key
        end
      end

      test "authenticates with bcrypt when configured prefix mismatch triggers known prefixes scan" do
        with_hash_strategy(:bcrypt) do
          original_prefix = ApiKeys.configuration.token_prefix
          begin
            ApiKeys.configuration.token_prefix = -> { "pfx1_" }
            key = ApiKeys::ApiKey.create!(owner: @user, name: "BCrypt Prefix Key")
            token = key.token
            key = ApiKeys::ApiKey.find(key.id)

            # Change configured prefix to force known-prefix path
            ApiKeys.configuration.token_prefix = -> { "otherpfx_" }

            request = mock_request(headers: { "Authorization" => "Bearer #{token}" })
            mock_cache

            result = ApiKeys::Services::Authenticator.call(request)
            assert result.success?
            assert_equal key, result.api_key
          ensure
            ApiKeys.configuration.token_prefix = original_prefix
          end
        end
      end

      test "stale prefix cache cannot strand a valid bcrypt key" do
        with_hash_strategy(:bcrypt) do
          key = ApiKeys::ApiKey.create!(owner: @user, name: "BCrypt Cached Prefix")
          token = key.token
          cache = mock_cache(Authenticator::KNOWN_PREFIXES_CACHE_KEY => ["stale_"])

          result = Authenticator.call(mock_request(headers: { "Authorization" => "Bearer #{token}" }))

          assert result.success?
          assert_equal key.id, result.api_key.id
          assert(cache.recorded_writes.any? { |write| write.first == Authenticator::KNOWN_PREFIXES_CACHE_KEY })
        end
      end

      test "overfull prefix cache falls back to a bounded last4 lookup" do
        with_hash_strategy(:bcrypt) do
          key = ApiKeys::ApiKey.create!(owner: @user, name: "BCrypt Prefix Flood")
          token = key.token
          poisoned_prefixes = (Authenticator::MAX_KNOWN_PREFIXES + 1).times.map { |index| "p#{index}_" }
          mock_cache(Authenticator::KNOWN_PREFIXES_CACHE_KEY => poisoned_prefixes)

          result = Authenticator.call(mock_request(headers: { "Authorization" => "Bearer #{token}" }))

          assert result.success?
          assert_equal key.id, result.api_key.id
        end
      end

      test "authenticates successfully with valid token in custom header" do
        ApiKeys.configure { |config| config.header = "X-Api-Key" }
        request = mock_request(headers: { "X-Api-Key" => @token })
        mock_cache

        result = ApiKeys::Services::Authenticator.call(request)

        assert result.success?
        assert_equal @api_key, result.api_key
      end

      test "authenticates successfully with valid token in query parameter" do
        ApiKeys.configure { |config| config.query_param = "token" }
        request = mock_request(query_params: { "token" => @token })
        mock_cache

        result = ApiKeys::Services::Authenticator.call(request)

        assert result.success?
        assert_equal @api_key, result.api_key
      end

      test "authenticates successfully using cached result" do
        request = mock_request(headers: { "Authorization" => "Bearer #{@token}" })
        cache_key = "api_keys:v2:token:#{Digest::SHA256.hexdigest(@token)}"
        mock_cache(cache_key => @api_key.id)

        result = ApiKeys::Services::Authenticator.call(request)
        assert result.success?
        assert_equal @api_key, result.api_key
      end

      test "cached key id is reloaded and revoked keys fail immediately" do
        request = mock_request(headers: { "Authorization" => "Bearer #{@token}" })
        cache_key = "api_keys:v2:token:#{Digest::SHA256.hexdigest(@token)}"
        mock_cache(cache_key => @api_key.id)
        @api_key.revoke!

        result = ApiKeys::Services::Authenticator.call(request)

        refute result.success?
        assert_equal :revoked_key, result.error_code
      end

      test "a poisoned cache entry cannot authenticate a different key" do
        other_key = ApiKeys::ApiKey.create!(owner: @user, name: "Other Key")
        request = mock_request(headers: { "Authorization" => "Bearer #{@token}" })
        cache_key = "api_keys:v2:token:#{Digest::SHA256.hexdigest(@token)}"
        mock_cache(cache_key => other_key.id)

        result = ApiKeys::Services::Authenticator.call(request)

        assert result.success?
        assert_equal @api_key.id, result.api_key.id
      end

      test "legacy cached Active Record objects are ignored" do
        request = mock_request(headers: { "Authorization" => "Bearer #{@token}" })
        cache_key = "api_keys:v2:token:#{Digest::SHA256.hexdigest(@token)}"
        stale_key = ApiKeys::ApiKey.find(@api_key.id)
        stale_key.revoke!
        stale_key.revoked_at = nil
        mock_cache(cache_key => stale_key)

        result = ApiKeys::Services::Authenticator.call(request)

        refute result.success?
        assert_equal :revoked_key, result.error_code
      end

      test "cache failures fall back to database verification" do
        Rails.stubs(:cache).returns(FailingCache.new)
        request = mock_request(headers: { "Authorization" => "Bearer #{@token}" })

        result = ApiKeys::Services::Authenticator.call(request)

        assert result.success?
        assert_equal @api_key.id, result.api_key.id
      end

      test "nil cache ttl disables caching without raising" do
        ApiKeys.configuration.cache_ttl = nil
        Rails.expects(:cache).never

        result = ApiKeys::Services::Authenticator.call(
          mock_request(headers: { "Authorization" => "Bearer #{@token}" })
        )

        assert result.success?
      end

      test "caches nil when token does not match any key" do
        invalid_token = "invalid_token_string"
        request = mock_request(headers: { "Authorization" => "Bearer #{invalid_token}" })
        mock_cache # defaults to misses

        result = ApiKeys::Services::Authenticator.call(request)
        refute result.success?
        assert_equal :invalid_token, result.error_code
      end

      test "returns failure for missing token" do
        request = mock_request # No headers or params
        mock_cache
        result = ApiKeys::Services::Authenticator.call(request)

        refute result.success?
        assert_nil result.api_key
        assert_equal :missing_token, result.error_code
      end

      test "returns failure for invalid token" do
        request = mock_request(headers: { "Authorization" => "Bearer invalid_token" })
        mock_cache

        result = ApiKeys::Services::Authenticator.call(request)

        refute result.success?
        assert_nil result.api_key
        assert_equal :invalid_token, result.error_code
      end

      test "rejects oversized tokens before querying the database" do
        oversized_token = "ak_#{"a" * (ApiKeys::Services::Authenticator::MAX_TOKEN_BYTESIZE + 1)}"
        ApiKeys::ApiKey.expects(:find_by).never

        result = ApiKeys::Services::Authenticator.call(
          mock_request(headers: { "Authorization" => "Bearer #{oversized_token}" })
        )

        refute result.success?
        assert_equal :invalid_token, result.error_code
      end

      test "never writes plaintext credentials to debug logs" do
        ApiKeys.configuration.debug_logging = true
        secret = @token.dup
        messages = []
        Authenticator.stubs(:log_debug).with { |message| messages << message; true }
        Authenticator.stubs(:log_warn).with { |message| messages << message; true }

        Authenticator.call(mock_request(headers: { "Authorization" => "Bearer #{secret}" }))

        refute messages.any? { |message| message.include?(secret) },
          "plaintext API key was present in a log message"
      end

      test "authentication results have credential-safe inspection" do
        result = Authenticator.call(mock_request(headers: { "Authorization" => "Bearer #{@token}" }))
        inspected = result.inspect

        refute_includes inspected, @token
        refute_includes inspected, @api_key.token_digest
        assert_includes inspected, "api_key_id=#{@api_key.id}"
        assert_equal inspected, result.to_s
      end

      test "returns failure for revoked key" do
        @api_key.revoke!
        request = mock_request(headers: { "Authorization" => "Bearer #{@token}" })
        mock_cache

        result = ApiKeys::Services::Authenticator.call(request)

        refute result.success?
        assert_nil result.api_key
        assert_equal :revoked_key, result.error_code
      end

      test "returns failure for expired key" do
        @api_key.update_column(:expires_at, 1.hour.ago)
        request = mock_request(headers: { "Authorization" => "Bearer #{@token}" })
        mock_cache

        result = ApiKeys::Services::Authenticator.call(request)

        refute result.success?
        assert_nil result.api_key
        assert_equal :expired_key, result.error_code
      end

      test "does not execute callbacks directly because the controller enqueues them once" do
        request = mock_request(headers: { "Authorization" => "Bearer #{@token}" })
        calls = []
        ApiKeys.configure do |config|
          config.before_authentication = ->(context) { calls << [:before, context] }
          config.after_authentication = ->(context) { calls << [:after, context] }
        end

        mock_cache

        ApiKeys::Services::Authenticator.call(request)

        assert_empty calls
      end

      test "bcrypt lookup only compares candidates with the matching prefix and last4" do
        with_hash_strategy(:bcrypt) do
          first = ApiKeys::ApiKey.create!(owner: @user, name: "BCrypt Candidate One")
          second = ApiKeys::ApiKey.create!(owner: @user, name: "BCrypt Candidate Two")
          second = ApiKeys::ApiKey.create!(owner: @user, name: "BCrypt Candidate Three") while second.last4 == first.last4
          invalid_token = "#{first.prefix}#{"A" * 20}#{first.last4}"
          Digestor.expects(:match?).once.returns(false)

          result = Authenticator.call(
            mock_request(headers: { "Authorization" => "Bearer #{invalid_token}" })
          )

          refute result.success?
          assert_equal :invalid_token, result.error_code
        end
      end

      test "bcrypt candidate work is bounded for corrupted or hostile rows" do
        now = Time.current
        rows = (Authenticator::MAX_BCRYPT_CANDIDATES + 1).times.map do |index|
          {
            prefix: "overfull_",
            last4: "zzzz",
            digest_algorithm: "bcrypt",
            token_digest: "malformed-#{index}",
            scopes: "[]",
            metadata: "{}",
            requests_count: 0,
            created_at: now,
            updated_at: now
          }
        end
        ApiKeys::ApiKey.insert_all!(rows)
        Digestor.expects(:match?).never

        result = Authenticator.send(:find_bcrypt_key_by_last4, "overfull_abcdefghijklzzzz")

        assert_nil result
      end

      test "invalid cached identifiers are ignored safely" do
        ApiKeys::ApiKey.stubs(:find_by).raises(RangeError, "out of range")

        assert_nil Authenticator.send(:safe_find_by_id, "bad-cache-id")
      end

      test "existing sha256 keys authenticate after changing the generation strategy" do
        ApiKeys.configuration.hash_strategy = :bcrypt

        result = Authenticator.call(mock_request(headers: { "Authorization" => "Bearer #{@token}" }))

        assert result.success?
        assert_equal @api_key.id, result.api_key.id
      end

      test "typed keys fail closed after their type is removed from configuration" do
        ApiKeys.configuration.key_types = {
          temporary: { prefix: "tk", permissions: %w[read] }
        }
        key = @user.create_api_key!(name: "Typed Key", key_type: :temporary, scopes: %w[read])
        token = key.token
        ApiKeys.configuration.key_types = {}

        result = Authenticator.call(mock_request(headers: { "Authorization" => "Bearer #{token}" }))

        refute result.success?
        assert_equal :unknown_key_type, result.error_code
      end

      test "typed keys fail closed when their environment is blank or retired" do
        ApiKeys.configuration.key_types = {
          temporary: { prefix: "tk", permissions: %w[read] }
        }
        ApiKeys.configuration.environments = {
          test: { prefix_segment: "test" },
          live: { prefix_segment: "live" }
        }
        ApiKeys.configuration.current_environment = :test
        key = @user.create_api_key!(name: "Environment Key", key_type: :temporary, scopes: %w[read])
        token = key.token

        key.update_column(:environment, nil)
        blank_result = Authenticator.call(mock_request(headers: { "Authorization" => "Bearer #{token}" }))
        refute blank_result.success?
        assert_equal :unknown_environment, blank_result.error_code

        key.update_column(:environment, "test")
        ApiKeys.configuration.environments = { live: { prefix_segment: "live" } }
        retired_result = Authenticator.call(mock_request(headers: { "Authorization" => "Bearer #{token}" }))
        refute retired_result.success?
        assert_equal :unknown_environment, retired_result.error_code
      end

      test "strict environment isolation fails closed when its resolver raises" do
        ApiKeys.configuration.key_types = {
          secret: { prefix: "sk", permissions: %w[read] }
        }
        ApiKeys.configuration.strict_environment_isolation = true
        ApiKeys.configuration.current_environment = -> { raise "resolver failure" }
        key = @user.create_api_key!(
          name: "Resolver Failure",
          key_type: :secret,
          environment: :test,
          scopes: %w[read]
        )

        result = Authenticator.call(
          mock_request(headers: { "Authorization" => "Bearer #{key.token}" })
        )

        refute result.success?
        assert_equal :environment_misconfigured, result.error_code
      end

      test "https enforcement fails closed by default in production" do
        Rails.stubs(:env).returns(ActiveSupport::EnvironmentInquirer.new("production"))

        result = Authenticator.call(
          mock_request(headers: { "Authorization" => "Bearer #{@token}" }, protocol: "http://")
        )

        refute result.success?
        assert_equal :insecure_connection, result.error_code
      end

      # === Prefix changes are SAFE for existing keys ===
      # The initializer template used to warn "Once set, do NOT change or
      # existing keys will fail authentication!" — false on both strategies:
      # sha256 looks up by pure token digest (prefix never consulted), and
      # bcrypt scopes by the key's OWN stored prefix via the known-prefixes
      # scan. These pin that guarantee so it can't regress silently.

      test "existing sha256 keys keep authenticating after token_prefix changes" do
        # @token was minted under the default "ak_" prefix in setup.
        ApiKeys.configuration.token_prefix = -> { "vdb_" }

        result = Authenticator.call(mock_request(headers: { "Authorization" => "Bearer #{@token}" }))

        assert result.success?, "a prefix change must never strand existing keys"
        assert_equal @api_key.id, result.api_key.id
      end

      test "existing bcrypt keys keep authenticating after token_prefix changes" do
        with_hash_strategy(:bcrypt) do
          key = ApiKeys::ApiKey.create!(owner: @user, name: "Pre-rebrand Key")
          token = key.token

          ApiKeys.configuration.token_prefix = -> { "vdb_" }

          result = Authenticator.call(mock_request(headers: { "Authorization" => "Bearer #{token}" }))

          assert result.success?, "the known-prefixes scan must find keys minted under retired prefixes"
          assert_equal key.id, result.api_key.id
        end
      end
    end
  end
end
