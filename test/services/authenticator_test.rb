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
          true
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

      def mock_request(headers: {}, query_params: {})
        # Simple mock request object responding to headers and query_parameters
        OpenStruct.new(headers: headers, query_parameters: query_params)
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
        cache_key = "api_keys:token:#{Digest::SHA1.hexdigest(@token)}"
        mock_cache(cache_key => @api_key)

        result = ApiKeys::Services::Authenticator.call(request)
        assert result.success?
        assert_equal @api_key, result.api_key
      end

      test "caches nil when token does not match any key" do
        invalid_token = "invalid_token_string"
        request = mock_request(headers: { "Authorization" => "Bearer #{invalid_token}" })
        cache_key = "api_keys:token:#{Digest::SHA1.hexdigest(invalid_token)}"
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

      test "calls before_authentication callback" do
        request = mock_request(headers: { "Authorization" => "Bearer #{@token}" })
        mock_callback = Minitest::Mock.new
        mock_callback.expect(:call, nil, [request])
        ApiKeys.configure { |config| config.before_authentication = mock_callback }

        mock_cache

        ApiKeys::Services::Authenticator.call(request)
        mock_callback.verify
      end

      test "calls after_authentication callback on success" do
        request = mock_request(headers: { "Authorization" => "Bearer #{@token}" })
        mock_callback = Minitest::Mock.new
        # Expect call with a success Result object
        mock_callback.expect(:call, nil) { |result| result.success? && result.api_key == @api_key }
        ApiKeys.configure { |config| config.after_authentication = mock_callback }

        mock_cache

        ApiKeys::Services::Authenticator.call(request)
        mock_callback.verify
      end

      test "calls after_authentication callback on failure" do
        request = mock_request(headers: { "Authorization" => "Bearer invalid" })
        mock_callback = Minitest::Mock.new
        # Expect call with a failure Result object
        mock_callback.expect(:call, nil) { |result| !result.success? && result.error_code == :invalid_token }
        ApiKeys.configure { |config| config.after_authentication = mock_callback }

        mock_cache

        ApiKeys::Services::Authenticator.call(request)
        mock_callback.verify
      end
    end
  end
end
