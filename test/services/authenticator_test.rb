# frozen_string_literal: true

require "test_helper"
require "ostruct"

module Apikeys
  module Services
    class AuthenticatorTest < Apikeys::Test
      def setup
        super
        @user = User.create!(name: "Auth User")
        @api_key = Models::ApiKey.create!(owner: @user, name: "Auth Key")
        @token = @api_key.token # Grab the plaintext token after creation
        # Ensure the key is reloaded to clear the plaintext token reader
        @api_key = Models::ApiKey.find(@api_key.id)
        assert_nil @api_key.token # Verify plaintext token is gone
      end

      # === Helper Methods ===

      def mock_request(headers: {}, query_params: {})
        # Simple mock request object responding to headers and query_parameters
        OpenStruct.new(headers: headers, query_parameters: query_params)
      end

      def mock_cache
        # Simple mock cache for testing interactions
        @mock_cache ||= Minitest::Mock.new
        Rails.stubs(:cache).returns(@mock_cache) # Stub Rails.cache to return our mock
        @mock_cache
      end

      # === Test Cases ===

      test "authenticates successfully with valid token in Authorization header" do
        request = mock_request(headers: { "Authorization" => "Bearer #{@token}" })
        mock_cache.expect(:read, nil) # Cache miss
        mock_cache.expect(:write, true, ["apikeys:token:#{Digest::SHA1.hexdigest(@token)}", @api_key, { expires_in: 10 }]) # Cache write

        result = Authenticator.call(request)

        assert result.success?
        assert_equal @api_key, result.api_key
        assert_nil result.error_code
        mock_cache.verify
      end

      test "authenticates successfully with valid token in custom header" do
        Apikeys.configure { |config| config.header = "X-Api-Key" }
        request = mock_request(headers: { "X-Api-Key" => @token })
        mock_cache.expect(:read, nil) # Cache miss
        mock_cache.expect(:write, true, ["apikeys:token:#{Digest::SHA1.hexdigest(@token)}", @api_key, { expires_in: 10 }]) # Cache write

        result = Authenticator.call(request)

        assert result.success?
        assert_equal @api_key, result.api_key
        mock_cache.verify
      end

      test "authenticates successfully with valid token in query parameter" do
        Apikeys.configure { |config| config.query_param = "token" }
        request = mock_request(query_params: { "token" => @token })
        mock_cache.expect(:read, nil) # Cache miss
        mock_cache.expect(:write, true, ["apikeys:token:#{Digest::SHA1.hexdigest(@token)}", @api_key, { expires_in: 10 }]) # Cache write

        result = Authenticator.call(request)

        assert result.success?
        assert_equal @api_key, result.api_key
        mock_cache.verify
      end

      test "authenticates successfully using cached result" do
        request = mock_request(headers: { "Authorization" => "Bearer #{@token}" })
        cache_key = "apikeys:token:#{Digest::SHA1.hexdigest(@token)}"
        mock_cache.expect(:read, @api_key) # Cache hit with the ApiKey object
        # No DB lookup or write expected

        # Ensure find is not called by stubbing it out
        Authenticator.stub :find_and_verify_key, ->(*) { flunk "DB lookup should not happen when cached" } do
          result = Authenticator.call(request)
          assert result.success?
          assert_equal @api_key, result.api_key
        end
        mock_cache.verify
      end

      test "caches nil when token does not match any key" do
        invalid_token = "invalid_token_string"
        request = mock_request(headers: { "Authorization" => "Bearer #{invalid_token}" })
        cache_key = "apikeys:token:#{Digest::SHA1.hexdigest(invalid_token)}"
        mock_cache.expect(:read, nil) # Cache miss
        mock_cache.expect(:write, true, [cache_key, nil, { expires_in: 10 }]) # Cache write with nil

        result = Authenticator.call(request)
        refute result.success?
        assert_equal :invalid_token, result.error_code
        mock_cache.verify
      end

      test "returns failure for missing token" do
        request = mock_request # No headers or params
        # No cache interaction expected for missing token
        result = Authenticator.call(request)

        refute result.success?
        assert_nil result.api_key
        assert_equal :missing_token, result.error_code
      end

      test "returns failure for invalid token" do
        request = mock_request(headers: { "Authorization" => "Bearer invalid_token" })
        mock_cache.expect(:read, nil) # Cache miss
        mock_cache.expect(:write, true, ["apikeys:token:#{Digest::SHA1.hexdigest("invalid_token")}", nil, { expires_in: 10 }]) # Cache write nil

        result = Authenticator.call(request)

        refute result.success?
        assert_nil result.api_key
        assert_equal :invalid_token, result.error_code
        mock_cache.verify
      end

      test "returns failure for revoked key" do
        @api_key.revoke!
        request = mock_request(headers: { "Authorization" => "Bearer #{@token}" })
        mock_cache.expect(:read, nil) # Cache miss
        # Note: find_and_verify_key will still find the key, but it's inactive
        # It will cache the found (but inactive) key
        mock_cache.expect(:write, true, ["apikeys:token:#{Digest::SHA1.hexdigest(@token)}", @api_key, { expires_in: 10 }])

        result = Authenticator.call(request)

        refute result.success?
        assert_nil result.api_key # Success result should clear api_key
        assert_equal :revoked_key, result.error_code
        mock_cache.verify
      end

      test "returns failure for expired key" do
        @api_key.update_column(:expires_at, 1.hour.ago)
        request = mock_request(headers: { "Authorization" => "Bearer #{@token}" })
        mock_cache.expect(:read, nil) # Cache miss
        mock_cache.expect(:write, true, ["apikeys:token:#{Digest::SHA1.hexdigest(@token)}", @api_key, { expires_in: 10 }])

        result = Authenticator.call(request)

        refute result.success?
        assert_nil result.api_key
        assert_equal :expired_key, result.error_code
        mock_cache.verify
      end

      test "calls before_authentication callback" do
        request = mock_request(headers: { "Authorization" => "Bearer #{@token}" })
        mock_callback = Minitest::Mock.new
        mock_callback.expect(:call, nil, [request])
        Apikeys.configure { |config| config.before_authentication = mock_callback }

        mock_cache.expect(:read, nil) # Cache miss
        mock_cache.expect(:write, true, [any_parameters]) # Ignore cache write params

        Authenticator.call(request)
        mock_callback.verify
      end

      test "calls after_authentication callback on success" do
        request = mock_request(headers: { "Authorization" => "Bearer #{@token}" })
        mock_callback = Minitest::Mock.new
        # Expect call with a success Result object
        mock_callback.expect(:call, nil) { |result| result.success? && result.api_key == @api_key }
        Apikeys.configure { |config| config.after_authentication = mock_callback }

        mock_cache.expect(:read, nil)
        mock_cache.expect(:write, true, [any_parameters])

        Authenticator.call(request)
        mock_callback.verify
      end

      test "calls after_authentication callback on failure" do
        request = mock_request(headers: { "Authorization" => "Bearer invalid" })
        mock_callback = Minitest::Mock.new
        # Expect call with a failure Result object
        mock_callback.expect(:call, nil) { |result| !result.success? && result.error_code == :invalid_token }
        Apikeys.configure { |config| config.after_authentication = mock_callback }

        mock_cache.expect(:read, nil)
        mock_cache.expect(:write, true, [any_parameters])

        Authenticator.call(request)
        mock_callback.verify
      end
    end
  end
end
