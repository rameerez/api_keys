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
