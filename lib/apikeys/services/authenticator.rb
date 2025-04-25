# frozen_string_literal: true

require "active_support/cache"
require "active_support/core_ext/object/blank"
require_relative "../models/api_key"
require_relative "../services/digestor"

module Apikeys
  module Services
    # Authenticates an incoming request by extracting and verifying an API key.
    class Authenticator
      # Result object for authentication attempts.
      Result = Struct.new(:success?, :api_key, :error_code, :message, keyword_init: true) do
        def self.success(api_key)
          new(success?: true, api_key: api_key)
        end

        def self.failure(error_code:, message:)
          new(success?: false, error_code: error_code, message: message)
        end
      end

      # Authenticates the request.
      #
      # @param request [ActionDispatch::Request] The incoming request object.
      # @return [Apikeys::Services::Authenticator::Result] The result of the authentication attempt.
      def self.call(request)
        config = Apikeys.configuration
        config.before_authentication&.call(request)

        token = extract_token(request, config)

        unless token
          result = Result.failure(error_code: :missing_token, message: "API token is missing")
          config.after_authentication&.call(result)
          return result
        end

        api_key = find_and_verify_key(token, config)

        result = if api_key&.active?
                   # TODO: Optionally update last_used_at and requests_count
                   Result.success(api_key)
                 elsif api_key&.revoked?
                   Result.failure(error_code: :revoked_key, message: "API key has been revoked")
                 elsif api_key&.expired?
                   Result.failure(error_code: :expired_key, message: "API key has expired")
                 else # Not found or mismatch
                   Result.failure(error_code: :invalid_token, message: "API token is invalid")
                 end

        config.after_authentication&.call(result)
        result
      end

      private

      # Extracts the token string from the request headers or query parameters.
      def self.extract_token(request, config)
        # Check header first (preferred)
        if config.header.present?
          header_value = request.headers[config.header]
          if header_value
            # Handle "Bearer <token>" scheme
            match = header_value.match(/^Bearer\s+(.*)$/i)
            return match[1] if match
            # Fallback: return the raw header value if no Bearer scheme
            return header_value
          end
        end

        # Check query parameter as fallback (if configured)
        if config.query_param.present?
          param_value = request.query_parameters[config.query_param]
          return param_value if param_value.present?
        end

        nil # No token found
      end

      # Finds the ApiKey record corresponding to the token, verifying the digest.
      # Uses caching if enabled.
      def self.find_and_verify_key(token, config)
        cache_key = "apikeys:token:#{Digest::SHA1.hexdigest(token)}" # Cache key based on token hash
        cache_ttl = config.cache_ttl.to_i

        if cache_ttl > 0
          cached_result = Rails.cache.read(cache_key)
          # Return cached result only if it's a definitive miss (nil) or a success (ApiKey instance)
          # Avoid caching intermediate failure states like expired/revoked, as status can change.
          return cached_result if cached_result.is_a?(Apikeys::ApiKey) || cached_result.nil?
        end

        # Cache miss or TTL=0: Perform DB lookup
        # We need to iterate through potential keys because we don't know the hash algorithm a priori
        # In practice, digests should be unique, so this finds at most one.
        # TODO: Optimize: If all keys used the same hash strategy, we could hash the incoming token
        #       and lookup by digest directly. But supporting mixed strategies requires checking.

        # Extract prefix to potentially narrow down the search (minor optimization)
        prefix_candidate = token[/^.+?_/] # Extract potential prefix like "ak_test_"
        possible_keys = if prefix_candidate
                          Apikeys::ApiKey.where(prefix: prefix_candidate)
                        else
                          Apikeys::ApiKey.all # Fallback if no discernible prefix
                        end

        verified_key = possible_keys.find do |key|
          Digestor.match?(token: token, stored_digest: key.token_digest, strategy: key.digest_algorithm.to_sym)
        end

        # Cache the result (either the found ApiKey instance or nil for a miss)
        Rails.cache.write(cache_key, verified_key, expires_in: cache_ttl) if cache_ttl > 0

        verified_key
      end

      def find_key_by_token(token)
        # 1. Check cache first (using digest as key)
        digest_info = Digestor.digest(token: token)
        digest = digest_info[:digest]
        cache_key = "apikeys:digest:#{digest[0..9]}" # Use digest prefix for cache key

        cached_result = Cache.read(cache_key)
        if cached_result
          # Cache hit: Could be an ApiKey instance or :not_found symbol
          # Handle potential inconsistencies: ensure it's a valid ApiKey or nil
          # if cached_result.is_a?(::ApiKey) && cached_result.token_digest == digest # Extra check if paranoid
          return cached_result if cached_result.is_a?(Apikeys::ApiKey) || cached_result.nil?
          # If cached result is invalid (e.g., :not_found symbol, or wrong type), proceed to DB lookup
        end

        # 2. DB lookup by digest
        # api_key = Apikeys.configuration.key_store_adapter.find_by_digest(digest)
        # For v1 ActiveRecordAdapter:
        api_key = Apikeys::ApiKey.find_by(token_digest: digest)

        # 3. Update cache
        Cache.write(cache_key, api_key) # Cache the found key or nil if not found

        api_key
      end
    end
  end
end
