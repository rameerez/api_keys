# frozen_string_literal: true

require "test_helper"

module ApiKeys
  module Helpers
    class TokenSessionTest < ApiKeys::Test
      def setup
        @session = {}
      end

      test "stores token from api_key object with token method" do
        api_key = mock("api_key")
        api_key.stubs(:respond_to?).with(:token).returns(true)
        api_key.stubs(:respond_to?).with(:id).returns(true)
        api_key.stubs(:token).returns("sk_test_abc123")
        api_key.stubs(:id).returns(42)

        result = TokenSession.store(@session, api_key)

        assert_equal "sk_test_abc123", result
        assert_equal({ "token" => "sk_test_abc123", "api_key_id" => "42" }, @session[:api_keys_new_token])
      end

      test "stores token from object without token method using to_s" do
        result = TokenSession.store(@session, "plain_token_string")

        assert_equal "plain_token_string", result
        assert_equal({ "token" => "plain_token_string", "api_key_id" => nil }, @session[:api_keys_new_token])
      end

      test "stores token with custom session key" do
        api_key = mock("api_key")
        api_key.stubs(:respond_to?).with(:token).returns(true)
        api_key.stubs(:respond_to?).with(:id).returns(false)
        api_key.stubs(:token).returns("custom_token")

        TokenSession.store(@session, api_key, key: :my_custom_key)

        assert_equal({ "token" => "custom_token", "api_key_id" => nil }, @session[:my_custom_key])
        assert_nil @session[:api_keys_new_token]
      end

      test "retrieve_once returns and clears token" do
        @session[:api_keys_new_token] = { "token" => "stored_token", "api_key_id" => "7" }

        result = TokenSession.retrieve_once(@session)

        assert_equal "stored_token", result
        assert_nil @session[:api_keys_new_token]
      end

      test "retrieve_once returns nil when no token stored" do
        result = TokenSession.retrieve_once(@session)

        assert_nil result
      end

      test "retrieve_once with custom key" do
        @session[:my_key] = { "token" => "my_token", "api_key_id" => nil }

        result = TokenSession.retrieve_once(@session, key: :my_key)

        assert_equal "my_token", result
        assert_nil @session[:my_key]
      end

      test "available? returns true when token present" do
        @session[:api_keys_new_token] = { "token" => "some_token", "api_key_id" => nil }

        assert TokenSession.available?(@session)
      end

      test "available? returns false when token not present" do
        refute TokenSession.available?(@session)
      end

      test "available? returns false when token is blank" do
        @session[:api_keys_new_token] = { "token" => "", "api_key_id" => nil }

        refute TokenSession.available?(@session)
      end

      test "available? with custom key" do
        @session[:custom] = { "token" => "token", "api_key_id" => nil }

        assert TokenSession.available?(@session, key: :custom)
        refute TokenSession.available?(@session, key: :other)
      end

      test "retrieve_once only releases a token for its bound API key" do
        @session[:api_keys_new_token] = { "token" => "key_one_secret", "api_key_id" => "1" }

        assert_nil TokenSession.retrieve_once(@session, api_key_id: 2)
        assert_nil @session[:api_keys_new_token]
      end

      test "legacy unbound session values are not released when key binding is required" do
        @session[:api_keys_new_token] = "legacy_secret"

        assert_nil TokenSession.retrieve_once(@session, api_key_id: 1)
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
