# frozen_string_literal: true

require "active_support/cache"
require "active_support/core_ext/object/blank"
require "digest"
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
        log_debug "[Apikeys Auth] Authenticator.call started for request: #{request.uuid}"
        config = Apikeys.configuration
        config.before_authentication&.call(request)

        token = extract_token(request, config)

        unless token
          log_debug "[Apikeys Auth] Token extraction failed."
          result = Result.failure(error_code: :missing_token, message: "API token is missing")
          config.after_authentication&.call(result)
          return result
        end

        log_debug "[Apikeys Auth] Token extracted successfully. Verifying..."
        # Pass the original token AND config to find_and_verify_key
        api_key = find_and_verify_key(token, config)

        result = if api_key&.active?
                   log_debug "[Apikeys Auth] Verification successful. Key ID: #{api_key.id}"
                   # TODO: Optionally update last_used_at and requests_count
                   Result.success(api_key)
                 elsif api_key&.revoked?
                   log_debug "[Apikeys Auth] Verification failed: Key revoked. Key ID: #{api_key.id}"
                   Result.failure(error_code: :revoked_key, message: "API key has been revoked")
                 elsif api_key&.expired?
                   log_debug "[Apikeys Auth] Verification failed: Key expired. Key ID: #{api_key.id}"
                   Result.failure(error_code: :expired_key, message: "API key has expired")
                 else # Not found, mismatch, or inactive
                   log_debug "[Apikeys Auth] Verification failed: Token invalid or key not found."
                   Result.failure(error_code: :invalid_token, message: "API token is invalid")
                 end

        log_debug "[Apikeys Auth] Authenticator.call finished. Result: #{result.inspect}"
        config.after_authentication&.call(result)
        result
      end

      private

      # Extracts the token string from the request headers or query parameters.
      def self.extract_token(request, config)
        # Check header first (preferred)
        if config.header.present?
          header_value = request.headers[config.header]
          log_debug "[Apikeys Auth] Checking header '#{config.header}': '#{header_value}'"
          if header_value
            # Handle "Bearer <token>" scheme
            match = header_value.match(/^Bearer\s+(.*)$/i)
            if match
              log_debug "[Apikeys Auth] Extracted token from Bearer scheme."
              return match[1]
            end
            # Fallback: return the raw header value if no Bearer scheme
            log_debug "[Apikeys Auth] No Bearer scheme, using raw header value as token."
            return header_value
          end
        end

        # Check query parameter as fallback (if configured)
        if config.query_param.present?
          param_value = request.query_parameters[config.query_param]
          log_debug "[Apikeys Auth] Checking query param '#{config.query_param}': '#{param_value}'"
          if param_value.present?
            log_debug "[Apikeys Auth] Extracted token from query parameter."
            return param_value
          end
        end

        log_debug "[Apikeys Auth] No token found in headers or query parameters."
        nil # No token found
      end

      # Finds the ApiKey record corresponding to the token and verifies it securely.
      # Uses caching if enabled.
      # @param token [String] The plaintext token from the request.
      # @param config [Apikeys::Configuration] The current configuration.
      # @return [Apikeys::ApiKey, nil] The verified ApiKey instance or nil.
      def self.find_and_verify_key(token, config)
        cache_key = "apikeys:token:#{Digest::SHA1.hexdigest(token)}" # Cache key based on token hash
        cache_ttl = config.cache_ttl.to_i
        log_debug "[Apikeys Auth] Verifying token. Cache key: #{cache_key}, TTL: #{cache_ttl}"

        if cache_ttl > 0
          cached_result = rails_cache&.read(cache_key)
          log_debug "[Apikeys Auth] Cache check: Result=#{cached_result.inspect}"
          # Return cached result ONLY if it's a valid ApiKey instance (a true cache hit)
          if cached_result.is_a?(Apikeys::ApiKey)
             log_debug "[Apikeys Auth] Cache HIT. Returning cached ApiKey ID: #{cached_result.id}"
             return cached_result
          elsif cached_result.nil?
             log_debug "[Apikeys Auth] Cache MISS. Proceeding to DB lookup."
             # Continue execution if it's a cache miss (nil)
          else
             # Handle unexpected cache values (e.g., old symbol :not_found)
             log_warn "[Apikeys Auth] Invalid cache value found: #{cached_result.inspect}. Proceeding to DB lookup."
          end
        end

        # --- Cache miss or TTL=0: Perform DB lookup & verification ---
        log_debug "[Apikeys Auth] Performing DB lookup and verification."

        # 1. Determine the expected hashing strategy (assuming single strategy for now)
        strategy = config.hash_strategy.to_sym
        log_debug "[Apikeys Auth] Using strategy: #{strategy}"

        # 2. For bcrypt (or strategies needing secure compare): Find potential matches by prefix
        verified_key = nil
        if strategy == :bcrypt
          # Match the standard prefix format: ak_{env}_ where {env} is one or more letters
          prefix_candidate = token[/^ak_[a-z]+_/i]
          log_debug "[Apikeys Auth] Extracted prefix: #{prefix_candidate}"

          possible_keys_scope = if prefix_candidate
                                  Apikeys::ApiKey.where(prefix: prefix_candidate, digest_algorithm: 'bcrypt')
                                else
                                  log_warn "[Apikeys Auth] Token prefix missing or invalid, cannot perform DB lookup."
                                  Apikeys::ApiKey.none # Return an empty relation
                                end

          log_debug "[Apikeys Auth] DB Query Scope SQL: #{possible_keys_scope.to_sql}" if possible_keys_scope.respond_to?(:to_sql)
          possible_keys = possible_keys_scope.to_a
          log_debug "[Apikeys Auth] Found #{possible_keys.count} potential key(s) with matching prefix and algorithm."

          verified_key = possible_keys.find do |key|
            match_result = Digestor.match?(token: token, stored_digest: key.token_digest, strategy: :bcrypt)
            log_debug "[Apikeys Auth] Comparing with Key ID: #{key.id}. Match result: #{match_result}"
            match_result
          end
        else
          log_warn "[Apikeys Auth] Authentication attempt with unsupported hash strategy: #{strategy}"
        end

        log_debug "[Apikeys Auth] DB Verification result: #{verified_key ? "Key ID: #{verified_key.id}" : 'No match'}"
        # --- End DB Lookup ---

        # Cache the result (either the found ApiKey instance or nil for a miss)
        if cache_ttl > 0 && rails_cache
          log_debug "[Apikeys Auth] Writing result to cache. Key: #{cache_key}, Value: #{verified_key.inspect}"
          rails_cache.write(cache_key, verified_key, expires_in: cache_ttl)
        end

        verified_key
      end

      # Helper for conditional debug logging
      def self.log_debug(message)
        if Apikeys.configuration.debug_logging && logger
          logger.debug(message)
        end
      end

      # Helper for conditional warning logging
      def self.log_warn(message)
        # Warnings are logged regardless of debug flag, if logger available
        logger.warn(message) if logger
      end

      # Helper for getting the logger instance
      def self.logger
        defined?(Rails) ? Rails.logger : nil
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
