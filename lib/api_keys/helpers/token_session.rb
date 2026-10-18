# frozen_string_literal: true

require "active_support/cache"
require "active_support/core_ext/numeric/time"
require "active_support/message_encryptor"
require "digest"
require "json"
require "securerandom"
require_relative "../logging"

module ApiKeys
  module Helpers
    # Helper for managing API key tokens in the session.
    #
    # Secret keys can only be shown once (immediately after creation) because
    # the plaintext token is not stored in the database. This helper provides
    # a clean interface for the "show token once" pattern:
    #
    # 1. After creating a key, store an encrypted, short-lived handoff in the session
    # 2. On the success page, decrypt, retrieve, and clear the token
    # 3. If the user refreshes, the token is gone
    #
    # Deleting the payload from the session only consumes it in that session.
    # A copy of the session taken before retrieval (a copied CookieStore
    # cookie, or two requests racing with the same cookie) would still carry
    # it. So each handoff also has a random ID, and the first retrieval
    # records an atomic consumption marker for that ID in `Rails.cache`
    # (`write(..., unless_exist: true)`). Any later retrieval of the same
    # handoff finds the marker and gets nil. This guarantee needs a cache store
    # that every application process shares and that implements
    # `unless_exist:` atomically. With `ActiveSupport::Cache::NullStore` the
    # marker cannot be recorded, so deleting the payload from the session is
    # the only protection, as it was before 0.5.1.
    #
    # @example In your controller
    #   # After creating a key:
    #   def create
    #     @api_key = current_org.create_api_key!(...)
    #     ApiKeys::Helpers::TokenSession.store(session, @api_key)
    #     redirect_to success_path
    #   end
    #
    #   # On the success page:
    #   def success
    #     @token = ApiKeys::Helpers::TokenSession.retrieve_once(session)
    #     redirect_to index_path, alert: "Token already shown" unless @token
    #   end
    #
    class TokenSession
      extend ApiKeys::Logging

      # Default session key for storing the token
      DEFAULT_SESSION_KEY = :api_keys_new_token
      MAX_TOKEN_BYTESIZE = 512
      MAX_CIPHERTEXT_BYTESIZE = 4096
      MAX_KEY_ID_BYTESIZE = 128
      # The wire format is unchanged since 0.4.0, so processes on 0.5.0 and
      # 0.5.1 can read each other's handoffs during a rolling deploy. 0.5.1
      # adds a random handoff ID inside the encrypted payload.
      HANDOFF_VERSION = 2
      HANDOFF_TTL = 10.minutes
      HANDOFF_ID_PATTERN = /\A[A-Za-z0-9_-]{22,64}\z/
      CONSUMPTION_CACHE_NAMESPACE = "api_keys:v1:token_handoff_consumed"
      ENCRYPTION_CIPHER = "aes-256-gcm"
      ENCRYPTION_SALT = "api_keys/token_session/v2"
      ENCRYPTION_PURPOSE = "api_keys.token_session"
      JSON_SERIALIZER = Module.new do
        module_function

        def dump(value)
          JSON.generate(value)
        end

        def load(value)
          JSON.parse(value)
        end
      end

      class << self
        # Store an encrypted API key-token handoff in the session for later retrieval.
        #
        # @param session [ActionDispatch::Request::Session] The Rails session
        # @param api_key [ApiKeys::ApiKey] The newly created API key
        # @param key [Symbol] Optional custom session key (default: :api_keys_new_token)
        # @return [String] The token that was stored
        def store(session, api_key, key: DEFAULT_SESSION_KEY)
          token = api_key.respond_to?(:token) ? api_key.token : api_key.to_s
          unless valid_token_payload?(token)
            raise ArgumentError, "Cannot store an invalid API key token in the session"
          end

          api_key_id = normalize_api_key_id(api_key.id) if api_key.respond_to?(:id)
          encrypted_payload = token_encryptor.encrypt_and_sign(
            { "token" => token, "api_key_id" => api_key_id, "handoff_id" => SecureRandom.urlsafe_base64(24) },
            expires_in: HANDOFF_TTL,
            purpose: ENCRYPTION_PURPOSE
          )
          session[key] = {
            "version" => HANDOFF_VERSION,
            "ciphertext" => encrypted_payload,
            "api_key_id" => api_key_id
          }
          token
        end

        # Retrieve and clear the token from the session.
        # Returns nil if no token is stored (e.g., page was refreshed), or if
        # this handoff was already retrieved through any copy of the session.
        #
        # @param session [ActionDispatch::Request::Session] The Rails session
        # @param key [Symbol] Optional custom session key (default: :api_keys_new_token)
        # @return [String, nil] The token, or nil if not present
        def retrieve_once(session, key: DEFAULT_SESSION_KEY, api_key: nil, api_key_id: nil)
          payload = session.delete(key)
          expected_id = normalize_api_key_id(api_key_id || (api_key.id if api_key.respond_to?(:id)))

          # Plain string payloads from older versions remain readable only when
          # the caller does not request ID binding.
          return payload if expected_id.nil? && valid_token_payload?(payload)
          decoded_payload = decode_payload(payload)
          return nil unless decoded_payload

          # Any authentic retrieval attempt uses the handoff up, matching the
          # session deletion above: a mismatched or replayed attempt never
          # leaves the handoff available to a later one.
          return nil unless consume_handoff(decoded_payload)

          token = decoded_payload["token"] || decoded_payload[:token]
          stored_id = decoded_payload["api_key_id"] || decoded_payload[:api_key_id]
          return nil if expected_id && stored_id.to_s != expected_id.to_s
          return nil unless valid_token_payload?(token)

          token
        end

        # Check if a token is available in the session without removing it.
        # Useful for conditional rendering.
        #
        # @param session [ActionDispatch::Request::Session] The Rails session
        # @param key [Symbol] Optional custom session key (default: :api_keys_new_token)
        # @return [Boolean] true if a token is stored
        def available?(session, key: DEFAULT_SESSION_KEY, api_key: nil, api_key_id: nil)
          payload = session[key]
          expected_id = normalize_api_key_id(api_key_id || (api_key.id if api_key.respond_to?(:id)))

          return valid_token_payload?(payload) if payload.is_a?(String) && expected_id.nil?
          decoded_payload = decode_payload(payload)
          return false unless decoded_payload

          token = decoded_payload["token"] || decoded_payload[:token]
          stored_id = decoded_payload["api_key_id"] || decoded_payload[:api_key_id]
          return false if expected_id && stored_id.to_s != expected_id.to_s
          return false unless valid_token_payload?(token)

          !handoff_consumed?(decoded_payload)
        end

        private

        def decode_payload(payload)
          return nil unless payload.is_a?(Hash)

          version_present = payload.key?("version") || payload.key?(:version)
          return legacy_payload(payload) unless version_present

          version = payload["version"] || payload[:version]
          return nil unless version == HANDOFF_VERSION

          ciphertext = payload["ciphertext"] || payload[:ciphertext]
          outer_id = normalize_api_key_id(payload["api_key_id"] || payload[:api_key_id])
          return nil unless ciphertext.is_a?(String) && ciphertext.bytesize <= MAX_CIPHERTEXT_BYTESIZE

          decoded = token_encryptor.decrypt_and_verify(ciphertext, purpose: ENCRYPTION_PURPOSE)
          return nil unless decoded.is_a?(Hash)

          inner_id = normalize_api_key_id(decoded["api_key_id"] || decoded[:api_key_id])
          return nil unless outer_id == inner_id

          # Handoffs written before 0.5.1 carry no ID; a present ID must be
          # well formed, since it names the consumption marker.
          handoff_id = decoded["handoff_id"]
          return nil unless handoff_id.nil? || (handoff_id.is_a?(String) && handoff_id.match?(HANDOFF_ID_PATTERN))

          decoded
        rescue ActiveSupport::MessageEncryptor::InvalidMessage, ArgumentError
          nil
        end

        def legacy_payload(payload)
          token = payload["token"] || payload[:token]
          stored_id = normalize_api_key_id(payload["api_key_id"] || payload[:api_key_id])
          return nil unless valid_token_payload?(token)

          { "token" => token, "api_key_id" => stored_id }
        rescue ArgumentError
          nil
        end

        # Records the consumption marker. Answers true only to the first
        # consumer of a handoff; every later one, and any cache failure, is
        # treated as "no token" (fail closed).
        def consume_handoff(decoded_payload)
          cache = consumption_cache
          return true unless cache

          marker = consumption_marker_key(decoded_payload)
          return true unless marker

          cache.write(marker, true, unless_exist: true, expires_in: HANDOFF_TTL) ? true : false
        rescue StandardError => error
          log_warn "[ApiKeys Security] Token handoff consumption could not be recorded (#{error.class}); withholding the token."
          false
        end

        def handoff_consumed?(decoded_payload)
          cache = consumption_cache
          return false unless cache

          marker = consumption_marker_key(decoded_payload)
          return false unless marker

          cache.exist?(marker)
        rescue StandardError => error
          log_warn "[ApiKeys Security] Token handoff consumption could not be checked (#{error.class})."
          true
        end

        # The cache that can enforce one-time retrieval across copies of a
        # session, or nil when there is none. NullStore accepts every write and
        # remembers nothing, so it cannot enforce anything.
        def consumption_cache
          cache = Rails.cache if defined?(Rails) && Rails.respond_to?(:cache)
          return nil if cache.nil? || cache.is_a?(ActiveSupport::Cache::NullStore)

          cache
        end

        # Handoffs written by 0.5.1 are named by their random ID. Handoffs
        # written before it have none; they are named by a domain-separated
        # digest of their token, which the encryption authenticates and which
        # is identical in every copy of the session. (Bare-string handoffs from
        # before 0.4.0 are returned before decoding and have no marker.)
        def consumption_marker_key(decoded_payload)
          handoff_id = decoded_payload["handoff_id"]
          return "#{CONSUMPTION_CACHE_NAMESPACE}:#{handoff_id}" if handoff_id

          token = decoded_payload["token"]
          return nil unless valid_token_payload?(token)

          "#{CONSUMPTION_CACHE_NAMESPACE}:token-#{Digest::SHA256.hexdigest("api_keys token handoff\0#{token}")}"
        end

        def normalize_api_key_id(value)
          return nil if value.nil?

          normalized = value.to_s
          valid = normalized.present? && normalized.valid_encoding? &&
            normalized.bytesize <= MAX_KEY_ID_BYTESIZE &&
            normalized.each_codepoint.none? { |codepoint| codepoint <= 0x20 || codepoint == 0x7f }
          raise ArgumentError, "API key ID is invalid" unless valid

          normalized
        rescue ArgumentError
          raise ArgumentError, "API key ID is invalid"
        end

        def token_encryptor
          application = Rails.application if defined?(Rails) && Rails.respond_to?(:application)
          unless application&.respond_to?(:key_generator)
            raise ArgumentError, "Rails.application.key_generator is required for secure token handoff"
          end

          key_length = ActiveSupport::MessageEncryptor.key_len(ENCRYPTION_CIPHER)
          encryption_key = application.key_generator.generate_key(ENCRYPTION_SALT, key_length)
          ActiveSupport::MessageEncryptor.new(
            encryption_key,
            cipher: ENCRYPTION_CIPHER,
            serializer: JSON_SERIALIZER
          )
        end

        def valid_token_payload?(token)
          token.is_a?(String) && token.present? && token.valid_encoding? &&
            token.bytesize <= MAX_TOKEN_BYTESIZE &&
            token.each_codepoint.none? { |codepoint| codepoint <= 0x20 || codepoint == 0x7f }
        rescue ArgumentError
          false
        end
      end
    end
  end
end
