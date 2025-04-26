# frozen_string_literal: true

require "active_support/cache"
require "active_support/core_ext/object/blank"
require "digest"
require_relative "../models/api_key"
require_relative "../services/digestor"
require_relative "../logging"

module ApiKeys
  module Services
    # Authenticates an incoming request by extracting and verifying an API key.
    class Authenticator
      extend ApiKeys::Logging

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
      # @return [ApiKeys::Services::Authenticator::Result] The result of the authentication attempt.
      def self.call(request)
        log_debug "[ApiKeys Auth] Authenticator.call started for request: #{request.uuid}"
        config = ApiKeys.configuration
        config.before_authentication&.call(request)

        # === HTTPS Check (Production Only) ===
        if defined?(Rails.env) && Rails.env.production? && config.https_only_production
          if request.protocol == "http://"
            warning_message = "[ApiKeys Security] API key authentication attempted over insecure HTTP connection in production."
            log_warn warning_message
            if config.https_strict_mode
              log_warn "[ApiKeys Security] Strict mode enabled: Aborting authentication."
              result = Result.failure(error_code: :insecure_connection, message: "API requests must be made over HTTPS in production.")
              config.after_authentication&.call(result)
              return result # Halt execution due to strict mode
            end
          end
        end
        # === End HTTPS Check ===

        token = extract_token(request, config)

        unless token
          log_debug "[ApiKeys Auth] Token extraction failed."
          result = Result.failure(error_code: :missing_token, message: "API token is missing")
          config.after_authentication&.call(result)
          return result
        end

        log_debug "[ApiKeys Auth] Token extracted successfully. Verifying..."
        # Pass the original token AND config to find_and_verify_key
        api_key = find_and_verify_key(token, config)

        result = if api_key&.active?
                   log_debug "[ApiKeys Auth] Verification successful. Key ID: #{api_key.id}"
                   # TODO: Optionally update last_used_at and requests_count
                   Result.success(api_key)
                 elsif api_key&.revoked?
                   log_debug "[ApiKeys Auth] Verification failed: Key revoked. Key ID: #{api_key.id}"
                   Result.failure(error_code: :revoked_key, message: "API key has been revoked")
                 elsif api_key&.expired?
                   log_debug "[ApiKeys Auth] Verification failed: Key expired. Key ID: #{api_key.id}"
                   Result.failure(error_code: :expired_key, message: "API key has expired")
                 else # Not found, mismatch, or inactive
                   log_debug "[ApiKeys Auth] Verification failed: Token invalid or key not found."
                   Result.failure(error_code: :invalid_token, message: "API token is invalid")
                 end

        log_debug "[ApiKeys Auth] Authenticator.call finished. Result: #{result.inspect}"
        config.after_authentication&.call(result)
        result
      end

      private

      # Extracts the token string from the request headers or query parameters.
      def self.extract_token(request, config)
        # Check header first (preferred)
        if config.header.present?
          header_value = request.headers[config.header]
          log_debug "[ApiKeys Auth] Checking header '#{config.header}': '#{header_value}'"
          if header_value
            # Handle "Bearer <token>" scheme
            match = header_value.match(/^Bearer\s+(.*)$/i)
            if match
              log_debug "[ApiKeys Auth] Extracted token from Bearer scheme."
              return match[1]
            end
            # Fallback: return the raw header value if no Bearer scheme
            log_debug "[ApiKeys Auth] No Bearer scheme, using raw header value as token."
            return header_value
          end
        end

        # Check query parameter as fallback (if configured)
        if config.query_param.present?
          param_value = request.query_parameters[config.query_param]
          log_debug "[ApiKeys Auth] Checking query param '#{config.query_param}': '#{param_value}'"
          if param_value.present?
            log_debug "[ApiKeys Auth] Extracted token from query parameter."
            return param_value
          end
        end

        log_debug "[ApiKeys Auth] No token found in headers or query parameters."
        nil # No token found
      end

      # Finds the ApiKey record corresponding to the token and verifies it securely.
      # Uses caching if enabled.
      # @param token [String] The plaintext token from the request.
      # @param config [ApiKeys::Configuration] The current configuration.
      # @return [ApiKeys::ApiKey, nil] The verified ApiKey instance or nil.
      def self.find_and_verify_key(token, config)
        cache_key = "api_keys:token:#{Digest::SHA1.hexdigest(token)}" # Cache key based on token hash
        cache_ttl = config.cache_ttl.to_i
        log_debug "[ApiKeys Auth] Verifying token. Cache key: #{cache_key}, TTL: #{cache_ttl}"

        if cache_ttl > 0
          cached_result = rails_cache&.read(cache_key)
          log_debug "[ApiKeys Auth] Cache check: Result=#{cached_result.inspect}"
          # Return cached result ONLY if it's a valid ApiKey instance (a true cache hit)
          if cached_result.is_a?(ApiKeys::ApiKey)
             log_debug "[ApiKeys Auth] Cache HIT. Returning cached ApiKey ID: #{cached_result.id}"
             return cached_result
          elsif cached_result.nil?
             log_debug "[ApiKeys Auth] Cache MISS. Proceeding to DB lookup."
             # Continue execution if it's a cache miss (nil)
          else
             # Handle unexpected cache values (e.g., old symbol :not_found)
             log_warn "[ApiKeys Auth] Invalid cache value found: #{cached_result.inspect}. Proceeding to DB lookup."
          end
        end

        # --- Cache miss or TTL=0: Perform DB lookup & verification ---
        log_debug "[ApiKeys Auth] Performing DB lookup and verification."

        # 1. Determine the expected hashing strategy (assuming single strategy for now)
        strategy = config.hash_strategy.to_sym
        log_debug "[ApiKeys Auth] Using strategy: #{strategy}"

        # 2. Find and verify the key based on the strategy.
        verified_key = nil
        if strategy == :bcrypt
          # Optimization: Check against the *configured* prefix first.
          configured_prefix = config.token_prefix.call
          matched_prefix = nil

          if token.start_with?(configured_prefix)
            log_debug "[ApiKeys Auth] Token matches configured prefix: #{configured_prefix}"
            matched_prefix = configured_prefix
          else
            # Fallback: If no match, check against all known prefixes (cached).
            log_debug "[ApiKeys Auth] Token does not match configured prefix. Checking known prefixes."
            known_prefixes = fetch_known_prefixes(config)
            # Sort by length descending to find the longest match first
            matched_prefix = known_prefixes.sort_by(&:length).reverse.find { |p| token.start_with?(p) }
            log_debug "[ApiKeys Auth] Known prefixes: #{known_prefixes}. Matched prefix for lookup: #{matched_prefix || 'None'}"
          end

          possible_keys_scope = if matched_prefix
                                  ApiKeys::ApiKey.where(prefix: matched_prefix, digest_algorithm: 'bcrypt')
                                else
                                  # This path is now less likely but covers cases where token matches no known prefix.
                                  log_warn "[ApiKeys Auth] Token does not start with the configured prefix or any known prefix. Cannot perform DB lookup."
                                  ApiKeys::ApiKey.none # Return an empty relation
                                end

          log_debug "[ApiKeys Auth] DB Query Scope SQL (bcrypt): #{possible_keys_scope.to_sql}" if possible_keys_scope.respond_to?(:to_sql)
          possible_keys = possible_keys_scope.to_a
          log_debug "[ApiKeys Auth] Found #{possible_keys.count} potential key(s) with matching prefix and algorithm for bcrypt."

          # Securely compare the provided token against the digests of potential keys
          verified_key = possible_keys.find do |key|
            match_result = Digestor.match?(token: token, stored_digest: key.token_digest, strategy: :bcrypt)
            log_debug "[ApiKeys Auth] Comparing with Key ID: #{key.id} (bcrypt). Match result: #{match_result}"
            match_result
          end

        elsif strategy == :sha256
          # For sha256, we hash the incoming token and look for an exact match
          # Note: Prefix lookup isn't useful here as the full hash is needed for the query.
          token_digest = Digest::SHA256.hexdigest(token)
          log_debug "[ApiKeys Auth] Calculated SHA256 digest for lookup: #{token_digest}"

          # Find the key directly by the calculated digest and algorithm
          verified_key = ApiKeys::ApiKey.find_by(token_digest: token_digest, digest_algorithm: 'sha256')

          if verified_key
            log_debug "[ApiKeys Auth] Found matching key by SHA256 digest. Key ID: #{verified_key.id}"
          else
            log_debug "[ApiKeys Auth] No key found matching the SHA256 digest."
          end

        else
          # Log unsupported strategy
          log_warn "[ApiKeys Auth] Authentication attempt with unsupported hash strategy: #{strategy}"
        end

        log_debug "[ApiKeys Auth] DB Verification result: #{verified_key ? "Key ID: #{verified_key.id}" : 'No match'}"
        # --- End DB Lookup ---

        # Cache the result (either the found ApiKey instance or nil for a miss)
        if cache_ttl > 0 && rails_cache
          log_debug "[ApiKeys Auth] Writing result to cache. Key: #{cache_key}, Value: #{verified_key.inspect}"
          rails_cache.write(cache_key, verified_key, expires_in: cache_ttl)
        end

        verified_key
      end

      # Helper to fetch (and cache) the distinct prefixes stored in the ApiKey table.
      def self.fetch_known_prefixes(config)
        cache_key = "api_keys:known_prefixes"
        cache_ttl = config.cache_ttl.to_i # Use the same TTL as key lookup for consistency

        if cache_ttl > 0
          cached_prefixes = rails_cache&.read(cache_key)
          return cached_prefixes if cached_prefixes.is_a?(Array)
          log_debug "[ApiKeys Auth] Known prefixes cache MISS. Fetching from DB."
        end

        # Fetch distinct, non-null prefixes from the database
        prefixes = ApiKeys::ApiKey.distinct.pluck(:prefix).compact

        if cache_ttl > 0 && rails_cache
          log_debug "[ApiKeys Auth] Writing known prefixes to cache. Key: #{cache_key}, Value: #{prefixes.inspect}"
          rails_cache.write(cache_key, prefixes, expires_in: cache_ttl)
        end

        prefixes
      end

      # Helper for accessing Rails cache safely
      def self.rails_cache
        defined?(Rails) ? Rails.cache : nil
      end

      # NOTE: Removing the incorrect private `find_key_by_token` method.
      # def find_key_by_token(token)
      #   ...
      # end
    end
  end
end
