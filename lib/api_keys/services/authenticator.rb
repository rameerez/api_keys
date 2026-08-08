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

      MAX_TOKEN_BYTESIZE = 512
      MAX_BCRYPT_CANDIDATES = 32
      MAX_KNOWN_PREFIXES = 1_024
      TOKEN_CACHE_NAMESPACE = "api_keys:v2:token"
      KNOWN_PREFIXES_CACHE_KEY = "api_keys:v2:known_prefixes"

      # Result object for authentication attempts.
      Result = Struct.new(:success?, :api_key, :error_code, :message, keyword_init: true) do
        def self.success(api_key)
          new(success?: true, api_key: api_key)
        end

        def self.failure(error_code:, message:)
          new(success?: false, error_code: error_code, message: message)
        end

        # Do not delegate to Struct's default inspection: it recursively inspects
        # the Active Record object and can expose token digests or public tokens.
        def inspect
          "#<#{self.class.name} success?=#{success?.inspect} api_key_id=#{api_key&.id.inspect} error_code=#{error_code.inspect}>"
        end

        alias_method :to_s, :inspect
      end

      # Authenticates the request.
      #
      # @param request [ActionDispatch::Request] The incoming request object.
      # @return [ApiKeys::Services::Authenticator::Result] The result of the authentication attempt.
      def self.call(request)
        request_uuid = request.uuid if request.respond_to?(:uuid)
        log_debug "[ApiKeys Auth] Authentication started for request #{request_uuid || '[unknown]'}"
        config = ApiKeys.configuration

        # === HTTPS Check (Production Only) ===
        if production_environment? && config.https_only_production
          unless secure_request?(request)
            warning_message = "[ApiKeys Security] API key authentication attempted over insecure HTTP connection in production."
            log_warn warning_message
            if config.https_strict_mode
              log_warn "[ApiKeys Security] Strict mode enabled: Aborting authentication."
              return Result.failure(error_code: :insecure_connection, message: "API requests must be made over HTTPS in production.")
            end
          end
        end
        # === End HTTPS Check ===

        token = extract_token(request, config)

        unless token
          log_debug "[ApiKeys Auth] Token extraction failed."
          return Result.failure(error_code: :missing_token, message: "API token is missing")
        end

        unless valid_token?(token)
          log_debug "[ApiKeys Auth] Rejected a malformed API token."
          return Result.failure(error_code: :invalid_token, message: "API token is invalid")
        end

        log_debug "[ApiKeys Auth] Token extracted successfully. Verifying..."
        # Pass the original token AND config to find_and_verify_key
        api_key = find_and_verify_key(token, config)

        result = if (configuration_failure = check_key_type_configuration(api_key, config) ||
                                                check_environment_configuration(api_key, config))
                   configuration_failure
                 elsif api_key&.active?
                   log_debug "[ApiKeys Auth] Verification successful. Key ID: #{api_key.id}"

                   # Check environment isolation if enabled
                   env_check_result = check_environment_isolation(api_key, config)
                   if env_check_result
                     env_check_result  # Return failure result
                   else
                     # TODO: Optionally update last_used_at and requests_count
                     Result.success(api_key)
                   end
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

        log_debug "[ApiKeys Auth] Authentication finished. Success: #{result.success?}; error code: #{result.error_code || 'none'}"
        result
      end

      # Extracts the token string from the request headers or query parameters.
      def self.extract_token(request, config)
        # Check header first (preferred)
        if config.header.present?
          header_value = request.headers[config.header]
          log_debug "[ApiKeys Auth] Checked configured authentication header. Present: #{!header_value.nil?}"
          unless header_value.nil?
            return header_value unless header_value.is_a?(String)

            # Handle "Bearer <token>" scheme
            match = header_value.match(/\ABearer[ \t]+(.+)\z/i)
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
          log_debug "[ApiKeys Auth] Checked configured query parameter. Present: #{param_value.present?}"
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
        cache_key = "#{TOKEN_CACHE_NAMESPACE}:#{Digest::SHA256.hexdigest(token)}"
        cache_ttl = normalized_cache_ttl(config.cache_ttl)
        log_debug "[ApiKeys Auth] Verifying token. Cache enabled: #{cache_ttl.positive?}"

        if cache_ttl > 0
          cached_id = safe_cache_read(cache_key)
          if cache_identifier?(cached_id)
            cached_key = safe_find_by_id(cached_id)
            if cached_key && verify_record_token(cached_key, token)
              log_debug "[ApiKeys Auth] Cache lookup hint verified for key ID: #{cached_key.id}"
              return cached_key
            end
          end
        end

        log_debug "[ApiKeys Auth] Performing DB lookup and verification."
        verified_key = find_sha256_key(token) || find_bcrypt_key(token, config)

        if cache_ttl > 0 && verified_key
          safe_cache_write(cache_key, verified_key.id, expires_in: cache_ttl)
        end

        verified_key
      end

      def self.find_sha256_key(token)
        token_digest = Digest::SHA256.hexdigest(token)
        key = ApiKeys::ApiKey.find_by(token_digest: token_digest, digest_algorithm: "sha256")
        key if key && verify_record_token(key, token)
      end

      def self.find_bcrypt_key(token, config)
        return nil if token.bytesize > Digestor::BCRYPT_MAX_SECRET_BYTESIZE

        cached_prefixes = fetch_known_prefixes(config)
        return find_bcrypt_key_by_last4(token) unless cached_prefixes

        key = find_bcrypt_key_for_prefixes(token, cached_prefixes)
        return key if key

        # Prefix caching is only a hint. A stale or poisoned cache entry must not
        # strand a valid bcrypt key, so retry once with authoritative DB values.
        fresh_prefixes = fetch_known_prefixes_from_database
        return find_bcrypt_key_by_last4(token) unless fresh_prefixes
        return nil if fresh_prefixes == cached_prefixes

        cache_ttl = normalized_cache_ttl(config.cache_ttl)
        safe_cache_write(KNOWN_PREFIXES_CACHE_KEY, fresh_prefixes, expires_in: cache_ttl) if cache_ttl > 0
        find_bcrypt_key_for_prefixes(token, fresh_prefixes)
      end

      def self.find_bcrypt_key_for_prefixes(token, prefixes)
        matched_prefix = prefixes.sort_by(&:bytesize).reverse_each.find { |prefix| token.start_with?(prefix) }
        return nil unless matched_prefix

        random_part = token.delete_prefix(matched_prefix)
        return nil if random_part.length < 4

        candidates = ApiKeys::ApiKey.where(
          prefix: matched_prefix,
          last4: random_part.last(4),
          digest_algorithm: "bcrypt"
        )
        find_verified_bcrypt_candidate(candidates, token)
      end

      # If a deployment has an unusually large number of historical prefixes,
      # avoid materializing them all in a request. `last4` is the last four
      # characters of the complete generated token as well as of its random
      # component, and every install has an index on that column.
      def self.find_bcrypt_key_by_last4(token)
        return nil if token.length < 4

        candidates = ApiKeys::ApiKey.where(last4: token.last(4), digest_algorithm: "bcrypt")
        find_verified_bcrypt_candidate(candidates, token)
      end

      def self.find_verified_bcrypt_candidate(relation, token)
        candidates = relation.limit(MAX_BCRYPT_CANDIDATES + 1).to_a

        if candidates.length > MAX_BCRYPT_CANDIDATES
          log_warn "[ApiKeys Security] Rejected an overfull bcrypt authentication candidate set."
          return nil
        end

        candidates.find do |candidate|
          candidate.prefix.is_a?(String) && token.start_with?(candidate.prefix) &&
            verify_record_token(candidate, token)
        end
      end

      def self.verify_record_token(api_key, token)
        strategy = api_key.digest_algorithm.to_s
        return false unless %w[sha256 bcrypt].include?(strategy)

        Digestor.match?(token: token, stored_digest: api_key.token_digest, strategy: strategy.to_sym)
      end

      # Helper to fetch (and cache) the distinct prefixes stored in the ApiKey table.
      def self.fetch_known_prefixes(config)
        cache_ttl = normalized_cache_ttl(config.cache_ttl)

        if cache_ttl > 0
          cached_prefixes = safe_cache_read(KNOWN_PREFIXES_CACHE_KEY)
          if cached_prefixes.is_a?(Array)
            sanitized_prefixes = sanitize_prefixes(cached_prefixes)
            return sanitized_prefixes if sanitized_prefixes

            log_warn "[ApiKeys Security] Ignored an overfull known-prefix cache entry."
            return nil
          end
          log_debug "[ApiKeys Auth] Known prefixes cache MISS. Fetching from DB."
        end

        # Fetch distinct, non-null prefixes from the database
        prefixes = fetch_known_prefixes_from_database

        if cache_ttl > 0 && prefixes
          safe_cache_write(KNOWN_PREFIXES_CACHE_KEY, prefixes, expires_in: cache_ttl)
        end

        prefixes
      end

      def self.fetch_known_prefixes_from_database
        prefixes = ApiKeys::ApiKey.distinct.limit(MAX_KNOWN_PREFIXES + 1).pluck(:prefix)
        sanitize_prefixes(prefixes)
      end

      def self.clear_known_prefixes_cache
        cache = rails_cache
        return unless cache

        cache.delete(KNOWN_PREFIXES_CACHE_KEY)
      rescue StandardError => error
        log_warn "[ApiKeys Auth] Cache delete failed (#{error.class}); continuing safely."
      end

      # Helper for accessing Rails cache safely
      def self.rails_cache
        defined?(Rails) ? Rails.cache : nil
      end

      def self.safe_cache_read(key)
        rails_cache&.read(key)
      rescue StandardError => error
        log_warn "[ApiKeys Auth] Cache read failed (#{error.class}); falling back to the database."
        nil
      end

      def self.safe_cache_write(key, value, expires_in:)
        rails_cache&.write(key, value, expires_in: expires_in)
      rescue StandardError => error
        log_warn "[ApiKeys Auth] Cache write failed (#{error.class}); authentication result was not cached."
        false
      end

      def self.normalized_cache_ttl(value)
        ttl = value.nil? ? 0 : value.to_f
        ttl.positive? ? ttl : 0
      rescue ArgumentError, TypeError
        0
      end

      def self.cache_identifier?(value)
        (value.is_a?(Integer) && value >= 0 && value.to_s.bytesize <= 128) ||
          (value.is_a?(String) && value.bytesize <= 128 && value.match?(/\A[[:alnum:]_-]+\z/))
      end

      def self.safe_find_by_id(id)
        ApiKeys::ApiKey.find_by(id: id)
      rescue StandardError => error
        log_warn "[ApiKeys Auth] Ignored an invalid cached key identifier (#{error.class})."
        nil
      end

      def self.sanitize_prefixes(prefixes)
        return nil unless prefixes.is_a?(Array)
        return nil if prefixes.length > MAX_KNOWN_PREFIXES

        prefixes.filter_map do |prefix|
          prefix if prefix.is_a?(String) && prefix.present? && prefix.valid_encoding? && prefix.bytesize <= 64
        end.uniq
      end

      def self.valid_token?(token)
        return false unless token.is_a?(String)
        return false if token.empty? || token.bytesize > MAX_TOKEN_BYTESIZE || !token.valid_encoding?

        token.each_codepoint.none? { |codepoint| codepoint <= 0x20 || codepoint == 0x7f }
      rescue ArgumentError
        false
      end

      def self.production_environment?
        defined?(Rails) && Rails.respond_to?(:env) && Rails.env.production?
      end

      def self.secure_request?(request)
        return request.ssl? if request.respond_to?(:ssl?)

        request.respond_to?(:protocol) && request.protocol == "https://"
      end

      def self.check_key_type_configuration(api_key, config)
        return nil unless api_key&.key_type.present?

        configured = config.key_types&.keys&.any? { |type| type.to_s == api_key.key_type.to_s }
        return nil if configured

        log_warn "[ApiKeys Security] Rejected API key ID #{api_key.id} because its key type is not configured."
        Result.failure(error_code: :unknown_key_type, message: "API key type is not configured")
      end

      def self.check_environment_configuration(api_key, config)
        return nil unless api_key&.key_type.present?

        configured = if api_key.environment.present? && config.environments.present?
                       config.environments.keys.any? { |environment| environment.to_s == api_key.environment.to_s }
                     else
                       api_key.environment.present?
                     end
        return nil if configured

        log_warn "[ApiKeys Security] Rejected API key ID #{api_key.id} because its environment is not configured."
        Result.failure(error_code: :unknown_environment, message: "API key environment is not configured")
      end

      # Check if the API key's environment matches the current environment
      # Returns a failure Result if there's a mismatch and strict isolation is enabled
      # Returns nil if the check passes or is not applicable
      def self.check_environment_isolation(api_key, config)
        return nil unless config.strict_environment_isolation

        # Untyped legacy keys predate environment support and remain exempt.
        key_env = api_key.environment
        return nil if key_env.blank? && api_key.key_type.blank?
        if key_env.blank?
          return Result.failure(
            error_code: :environment_misconfigured,
            message: "API key environment could not be verified"
          )
        end

        # Get current environment
        current_env_config = config.current_environment
        begin
          current_env = current_env_config.respond_to?(:call) ? current_env_config.call : current_env_config
        rescue StandardError => error
          log_warn "[ApiKeys Security] Current environment resolution failed (#{error.class})."
          return Result.failure(
            error_code: :environment_misconfigured,
            message: "API key environment could not be verified"
          )
        end

        # Normalize to string first, then check if blank
        # This ensures consistent string comparison and prevents edge cases with empty strings
        current_env = current_env.to_s
        key_env = key_env.to_s

        # Strict isolation must fail closed when the current environment cannot be resolved.
        if current_env.blank?
          log_warn "[ApiKeys Security] Strict environment isolation is enabled, but current_environment resolved to blank."
          return Result.failure(
            error_code: :environment_misconfigured,
            message: "API key environment could not be verified"
          )
        end

        if current_env != key_env
          log_debug "[ApiKeys Auth] Environment mismatch for key ID #{api_key.id}."
          return Result.failure(
            error_code: :environment_mismatch,
            message: "API key cannot be used in this environment"
          )
        end

        nil # Check passed
      end

      private_class_method :extract_token, :find_and_verify_key, :find_sha256_key,
                           :find_bcrypt_key, :find_bcrypt_key_for_prefixes,
                           :find_bcrypt_key_by_last4, :find_verified_bcrypt_candidate,
                           :verify_record_token, :fetch_known_prefixes,
                           :fetch_known_prefixes_from_database, :rails_cache,
                           :safe_cache_read, :safe_cache_write,
                           :normalized_cache_ttl, :cache_identifier?,
                           :safe_find_by_id, :sanitize_prefixes, :valid_token?,
                           :production_environment?, :secure_request?,
                           :check_key_type_configuration, :check_environment_configuration,
                           :check_environment_isolation
    end
  end
end
