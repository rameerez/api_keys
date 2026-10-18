# frozen_string_literal: true

require "test_helper"
require "active_support/message_encryptor"

module ApiKeys
  module Helpers
    class TokenSessionTest < ApiKeys::Test
      def setup
        super
        @session = {}
        encryption_key = "k" * ActiveSupport::MessageEncryptor.key_len("aes-256-gcm")
        @encryptor = ActiveSupport::MessageEncryptor.new(
          encryption_key,
          cipher: "aes-256-gcm",
          serializer: JSON
        )
        TokenSession.stubs(:token_encryptor).returns(@encryptor)
      end

      def use_cache(cache)
        Rails.stubs(:cache).returns(cache)
      end

      def bound_key(token, id)
        Struct.new(:token, :id).new(token, id)
      end

      test "stores token from api_key object with token method" do
        api_key = mock("api_key")
        api_key.stubs(:respond_to?).with(:token).returns(true)
        api_key.stubs(:respond_to?).with(:id).returns(true)
        api_key.stubs(:token).returns("sk_test_abc123")
        api_key.stubs(:id).returns(42)

        result = TokenSession.store(@session, api_key)

        assert_equal "sk_test_abc123", result
        payload = @session[:api_keys_new_token]
        assert_equal TokenSession::HANDOFF_VERSION, payload["version"]
        assert_equal "42", payload["api_key_id"]
        assert_predicate payload["ciphertext"], :present?
        refute_includes payload.inspect, "sk_test_abc123"
      end

      test "stores token from object without token method using to_s" do
        result = TokenSession.store(@session, "plain_token_string")

        assert_equal "plain_token_string", result
        payload = @session[:api_keys_new_token]
        assert_equal TokenSession::HANDOFF_VERSION, payload["version"]
        assert_nil payload["api_key_id"]
        refute_includes payload.inspect, "plain_token_string"
      end

      test "stores token with custom session key" do
        api_key = mock("api_key")
        api_key.stubs(:respond_to?).with(:token).returns(true)
        api_key.stubs(:respond_to?).with(:id).returns(false)
        api_key.stubs(:token).returns("custom_token")

        TokenSession.store(@session, api_key, key: :my_custom_key)

        assert_equal TokenSession::HANDOFF_VERSION, @session[:my_custom_key]["version"]
        refute_includes @session[:my_custom_key].inspect, "custom_token"
        assert_nil @session[:api_keys_new_token]
      end

      test "retrieve_once returns and clears token" do
        TokenSession.store(@session, "stored_token")

        result = TokenSession.retrieve_once(@session)

        assert_equal "stored_token", result
        assert_nil @session[:api_keys_new_token]
      end

      test "retrieve_once returns nil when no token stored" do
        result = TokenSession.retrieve_once(@session)

        assert_nil result
      end

      test "retrieve_once with custom key" do
        TokenSession.store(@session, "my_token", key: :my_key)

        result = TokenSession.retrieve_once(@session, key: :my_key)

        assert_equal "my_token", result
        assert_nil @session[:my_key]
      end

      test "available? returns true when token present" do
        TokenSession.store(@session, "some_token")

        assert TokenSession.available?(@session)
      end

      test "available? returns false when token not present" do
        refute TokenSession.available?(@session)
      end

      test "available? returns false when token is blank" do
        @session[:api_keys_new_token] = {
          "version" => TokenSession::HANDOFF_VERSION,
          "ciphertext" => "invalid",
          "api_key_id" => nil
        }

        refute TokenSession.available?(@session)
      end

      test "available? with custom key" do
        TokenSession.store(@session, "token", key: :custom)

        assert TokenSession.available?(@session, key: :custom)
        refute TokenSession.available?(@session, key: :other)
      end

      test "retrieve_once only releases a token for its bound API key" do
        api_key = mock("api_key")
        api_key.stubs(:respond_to?).with(:token).returns(true)
        api_key.stubs(:respond_to?).with(:id).returns(true)
        api_key.stubs(:token).returns("key_one_secret")
        api_key.stubs(:id).returns(1)
        TokenSession.store(@session, api_key)

        assert_nil TokenSession.retrieve_once(@session, api_key_id: 2)
        assert_nil @session[:api_keys_new_token]
      end

      test "legacy unbound session values are not released when key binding is required" do
        @session[:api_keys_new_token] = "legacy_secret"

        assert_nil TokenSession.retrieve_once(@session, api_key_id: 1)
      end

      test "legacy plaintext payloads remain readable for an in-flight upgrade handoff" do
        @session[:api_keys_new_token] = { "token" => "legacy_secret", "api_key_id" => "7" }

        assert_equal "legacy_secret", TokenSession.retrieve_once(@session, api_key_id: 7)
        assert_nil @session[:api_keys_new_token]
      end

      test "a malformed version marker cannot downgrade to a legacy plaintext handoff" do
        [nil, false, 1, TokenSession::HANDOFF_VERSION.to_s].each do |version|
          @session[:api_keys_new_token] = {
            "version" => version,
            "token" => "downgrade_secret",
            "api_key_id" => "7"
          }

          refute TokenSession.available?(@session, api_key_id: 7)
          assert_nil TokenSession.retrieve_once(@session, api_key_id: 7)
        end
      end

      test "tampered encrypted handoffs fail closed and are cleared" do
        TokenSession.store(@session, "tamper_protected_token")
        ciphertext = @session[:api_keys_new_token]["ciphertext"].dup
        ciphertext.setbyte(0, ciphertext.getbyte(0) ^ 1)
        @session[:api_keys_new_token]["ciphertext"] = ciphertext

        refute TokenSession.available?(@session)
        assert_nil TokenSession.retrieve_once(@session)
        assert_nil @session[:api_keys_new_token]
      end

      test "encrypted handoffs expire quickly and fail closed" do
        TokenSession.store(@session, "short_lived_token")

        travel TokenSession::HANDOFF_TTL + 1.second do
          refute TokenSession.available?(@session)
          assert_nil TokenSession.retrieve_once(@session)
        end
        assert_nil @session[:api_keys_new_token]
      end

      test "production encryptor derives an authenticated-encryption key from the Rails application" do
        TokenSession.unstub(:token_encryptor)
        key_length = ActiveSupport::MessageEncryptor.key_len(TokenSession::ENCRYPTION_CIPHER)
        key_generator = mock("application key generator")
        key_generator.expects(:generate_key)
                     .with(TokenSession::ENCRYPTION_SALT, key_length)
                     .returns("r" * key_length)
        application = mock("Rails application")
        application.stubs(:key_generator).returns(key_generator)
        Rails.stubs(:application).returns(application)

        encryptor = TokenSession.send(:token_encryptor)
        ciphertext = encryptor.encrypt_and_sign(
          { "token" => "derived_key_token" },
          purpose: TokenSession::ENCRYPTION_PURPOSE
        )

        assert_equal({ "token" => "derived_key_token" }, encryptor.decrypt_and_verify(
          ciphertext,
          purpose: TokenSession::ENCRYPTION_PURPOSE
        ))
      end

      test "store rejects missing plaintext tokens" do
        api_key = mock("api_key")
        api_key.stubs(:respond_to?).with(:token).returns(true)
        api_key.stubs(:token).returns(nil)

        assert_raises(ArgumentError) { TokenSession.store(@session, api_key) }
        assert_empty @session
      end

      # =======================================================================
      # 0.5.1: one-time retrieval across copies of the session
      # =======================================================================

      test "a copied pre-consumption session cannot recover the token again" do
        use_cache(ActiveSupport::Cache::MemoryStore.new)
        TokenSession.store(@session, bound_key("copied_cookie_token", 7))
        copied_cookie = @session.deep_dup

        assert_equal "copied_cookie_token", TokenSession.retrieve_once(@session, api_key_id: 7)
        assert_nil TokenSession.retrieve_once(copied_cookie, api_key_id: 7)
        assert_nil copied_cookie[:api_keys_new_token], "the replayed copy is cleared as well"
      end

      test "concurrent retrievals with the same session release the token once" do
        use_cache(ActiveSupport::Cache::MemoryStore.new)
        TokenSession.store(@session, bound_key("raced_token", 9))
        copies = Array.new(16) { @session.deep_dup }
        gate = Queue.new

        threads = copies.map do |copy|
          Thread.new do
            gate.pop
            TokenSession.retrieve_once(copy, api_key_id: 9)
          end
        end
        copies.size.times { gate << true }
        results = threads.map(&:value)

        assert_equal ["raced_token"], results.compact
      end

      test "available? reports a handoff consumed through another copy as gone" do
        use_cache(ActiveSupport::Cache::MemoryStore.new)
        TokenSession.store(@session, bound_key("visible_token", 3))
        copied_cookie = @session.deep_dup

        assert TokenSession.available?(copied_cookie, api_key_id: 3)
        TokenSession.retrieve_once(@session, api_key_id: 3)

        refute TokenSession.available?(copied_cookie, api_key_id: 3)
      end

      test "any authentic retrieval attempt consumes the handoff, even a mismatched one" do
        use_cache(ActiveSupport::Cache::MemoryStore.new)
        TokenSession.store(@session, bound_key("probed_token", 5))
        copied_cookie = @session.deep_dup

        assert_nil TokenSession.retrieve_once(@session, api_key_id: 6)
        assert_nil TokenSession.retrieve_once(copied_cookie, api_key_id: 5)
      end

      test "the consumption marker is atomic and outlives the handoff" do
        cache = ActiveSupport::Cache::MemoryStore.new
        use_cache(cache)
        TokenSession.store(@session, bound_key("marked_token", 4))
        cache.expects(:write)
             .with(regexp_matches(/\Aapi_keys:v1:token_handoff_consumed:[A-Za-z0-9_-]{32}\z/), true,
                   unless_exist: true, expires_in: TokenSession::HANDOFF_TTL)
             .returns(true)

        assert_equal "marked_token", TokenSession.retrieve_once(@session, api_key_id: 4)
      end

      test "each handoff carries its own random ID" do
        TokenSession.store(@session, bound_key("first_token", 1))
        first = @encryptor.decrypt_and_verify(@session[:api_keys_new_token]["ciphertext"],
                                              purpose: TokenSession::ENCRYPTION_PURPOSE)
        TokenSession.store(@session, bound_key("second_token", 2))
        second = @encryptor.decrypt_and_verify(@session[:api_keys_new_token]["ciphertext"],
                                               purpose: TokenSession::ENCRYPTION_PURPOSE)

        assert_match TokenSession::HANDOFF_ID_PATTERN, first["handoff_id"]
        refute_equal first["handoff_id"], second["handoff_id"]
        refute_includes @session.inspect, second["handoff_id"]
      end

      test "a cache failure withholds the token instead of risking a second release" do
        cache = ActiveSupport::Cache::MemoryStore.new
        cache.stubs(:write).raises(IOError, "cache unavailable")
        use_cache(cache)
        TokenSession.store(@session, bound_key("withheld_token", 8))

        assert_nil TokenSession.retrieve_once(@session, api_key_id: 8)
      end

      test "available? reports nothing when the cache cannot be read" do
        cache = ActiveSupport::Cache::MemoryStore.new
        cache.stubs(:exist?).raises(IOError, "cache unavailable")
        use_cache(cache)
        TokenSession.store(@session, bound_key("unverifiable_token", 6))
        warnings = []
        TokenSession.stubs(:log_warn).with { |message| warnings << message; true }

        refute TokenSession.available?(@session, api_key_id: 6)
        assert_equal ["[ApiKeys Security] Token handoff consumption could not be checked (IOError)."], warnings
        refute_includes warnings.join, "unverifiable_token"
        assert @session[:api_keys_new_token], "a failed check is read-only and leaves the handoff in place"
      end

      test "a cache that refuses the marker withholds the token" do
        cache = ActiveSupport::Cache::MemoryStore.new
        cache.stubs(:write).returns(false) # what Redis and Memcached answer on error, too
        use_cache(cache)
        TokenSession.store(@session, bound_key("refused_token", 8))

        assert_nil TokenSession.retrieve_once(@session, api_key_id: 8)
      end

      # Documented limitation, pinned so it stays visible: the consumption
      # marker lives only in the cache. If the cache loses it (flush, restart,
      # eviction) within the handoff lifetime, a copy of the session taken
      # before retrieval recovers the token again. Durable consumption state
      # is planned for 0.6.0; when it lands, this test must flip.
      test "losing the consumption marker re-opens replay for the rest of the handoff lifetime" do
        cache = ActiveSupport::Cache::MemoryStore.new
        use_cache(cache)
        TokenSession.store(@session, bound_key("marker_lost_token", 11))
        copied_cookie = @session.deep_dup
        second_copy = @session.deep_dup
        late_copy = @session.deep_dup

        assert_equal "marker_lost_token", TokenSession.retrieve_once(@session, api_key_id: 11)
        assert_nil TokenSession.retrieve_once(copied_cookie, api_key_id: 11), "replay is stopped while the marker exists"

        cache.clear

        assert_equal "marker_lost_token", TokenSession.retrieve_once(second_copy, api_key_id: 11),
                     "without the marker, a pre-retrieval copy recovers the token again"

        travel TokenSession::HANDOFF_TTL + 1.second do
          cache.clear
          assert_nil TokenSession.retrieve_once(late_copy, api_key_id: 11),
                     "the window closes when the handoff itself expires"
        end
      end

      test "handoffs written before 0.5.1 are also one-time" do
        use_cache(ActiveSupport::Cache::MemoryStore.new)
        @session[:api_keys_new_token] = {
          "version" => TokenSession::HANDOFF_VERSION,
          "ciphertext" => @encryptor.encrypt_and_sign({ "token" => "pre_051_token", "api_key_id" => "12" },
                                                      expires_in: TokenSession::HANDOFF_TTL,
                                                      purpose: TokenSession::ENCRYPTION_PURPOSE),
          "api_key_id" => "12"
        }
        copied_cookie = @session.deep_dup

        assert_equal "pre_051_token", TokenSession.retrieve_once(@session, api_key_id: 12)
        assert_nil TokenSession.retrieve_once(copied_cookie, api_key_id: 12)
      end

      test "an authentic payload with a malformed handoff ID fails closed" do
        use_cache(ActiveSupport::Cache::MemoryStore.new)
        ["short", "../../escape-the-namespace-0123456789", 42, ""].each do |handoff_id|
          @session[:api_keys_new_token] = {
            "version" => TokenSession::HANDOFF_VERSION,
            "ciphertext" => @encryptor.encrypt_and_sign(
              { "token" => "odd_id_token", "api_key_id" => "1", "handoff_id" => handoff_id },
              expires_in: TokenSession::HANDOFF_TTL,
              purpose: TokenSession::ENCRYPTION_PURPOSE
            ),
            "api_key_id" => "1"
          }

          refute TokenSession.available?(@session, api_key_id: 1), handoff_id.inspect
          assert_nil TokenSession.retrieve_once(@session, api_key_id: 1), handoff_id.inspect
        end
      end

      test "with NullStore the session deletion is the only protection" do
        use_cache(ActiveSupport::Cache::NullStore.new)
        TokenSession.store(@session, bound_key("null_store_token", 2))
        copied_cookie = @session.deep_dup

        assert_equal "null_store_token", TokenSession.retrieve_once(@session, api_key_id: 2)
        assert_nil TokenSession.retrieve_once(@session, api_key_id: 2), "the same session is still one-time"
        # The documented limitation: NullStore remembers nothing, so a copy
        # taken before retrieval still carries the handoff.
        assert_equal "null_store_token", TokenSession.retrieve_once(copied_cookie, api_key_id: 2)
      end

      test "without any Rails cache the session deletion is the only protection" do
        use_cache(nil)
        TokenSession.store(@session, bound_key("no_cache_token", 2))

        assert_equal "no_cache_token", TokenSession.retrieve_once(@session, api_key_id: 2)
        assert_nil TokenSession.retrieve_once(@session, api_key_id: 2)
      end

      test "session token payloads are structurally bounded" do
        assert_raises(ArgumentError) do
          TokenSession.store(@session, "a" * (TokenSession::MAX_TOKEN_BYTESIZE + 1))
        end
        assert_raises(ArgumentError) { TokenSession.store(@session, "token\nvalue") }
        assert_empty @session

        @session[:api_keys_new_token] = {
          "token" => "a" * (TokenSession::MAX_TOKEN_BYTESIZE + 1),
          "api_key_id" => "1"
        }
        refute TokenSession.available?(@session, api_key_id: 1)
        assert_nil TokenSession.retrieve_once(@session, api_key_id: 1)
      end
    end
  end
end
