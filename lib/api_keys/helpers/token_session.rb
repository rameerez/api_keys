# frozen_string_literal: true

require "active_support/core_ext/numeric/time"
require "active_support/message_encryptor"
require "json"

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
      # Default session key for storing the token
      DEFAULT_SESSION_KEY = :api_keys_new_token
      MAX_TOKEN_BYTESIZE = 512
      MAX_CIPHERTEXT_BYTESIZE = 4096
      MAX_KEY_ID_BYTESIZE = 128
      HANDOFF_VERSION = 2
      HANDOFF_TTL = 10.minutes
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
            { "token" => token, "api_key_id" => api_key_id },
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
        # Returns nil if no token is stored (e.g., page was refreshed).
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

          valid_token_payload?(token)
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
