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
        api_key.stubs(:token).returns("sk_test_abc123")

        result = TokenSession.store(@session, api_key)

        assert_equal "sk_test_abc123", result
        assert_equal "sk_test_abc123", @session[:api_keys_new_token]
      end

      test "stores token from object without token method using to_s" do
        result = TokenSession.store(@session, "plain_token_string")

        assert_equal "plain_token_string", result
        assert_equal "plain_token_string", @session[:api_keys_new_token]
      end

      test "stores token with custom session key" do
        api_key = mock("api_key")
        api_key.stubs(:respond_to?).with(:token).returns(true)
        api_key.stubs(:token).returns("custom_token")

        TokenSession.store(@session, api_key, key: :my_custom_key)

        assert_equal "custom_token", @session[:my_custom_key]
        assert_nil @session[:api_keys_new_token]
      end

      test "retrieve_once returns and clears token" do
        @session[:api_keys_new_token] = "stored_token"

        result = TokenSession.retrieve_once(@session)

        assert_equal "stored_token", result
        assert_nil @session[:api_keys_new_token]
      end

      test "retrieve_once returns nil when no token stored" do
        result = TokenSession.retrieve_once(@session)

        assert_nil result
      end

      test "retrieve_once with custom key" do
        @session[:my_key] = "my_token"

        result = TokenSession.retrieve_once(@session, key: :my_key)

        assert_equal "my_token", result
        assert_nil @session[:my_key]
      end

      test "available? returns true when token present" do
        @session[:api_keys_new_token] = "some_token"

        assert TokenSession.available?(@session)
      end

      test "available? returns false when token not present" do
        refute TokenSession.available?(@session)
      end

      test "available? returns false when token is blank" do
        @session[:api_keys_new_token] = ""

        refute TokenSession.available?(@session)
      end

      test "available? with custom key" do
        @session[:custom] = "token"

        assert TokenSession.available?(@session, key: :custom)
        refute TokenSession.available?(@session, key: :other)
      end
    end
  end
end
