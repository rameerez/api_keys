# frozen_string_literal: true

module ApiKeys
  module Helpers
    # Helper for managing API key tokens in the session.
    #
    # Secret keys can only be shown once (immediately after creation) because
    # the plaintext token is not stored in the database. This helper provides
    # a clean interface for the "show token once" pattern:
    #
    # 1. After creating a key, store the token in the session
    # 2. On the success page, retrieve (and clear) the token
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

      class << self
        # Store an API key's token in the session for later retrieval.
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

          api_key_id = api_key.id if api_key.respond_to?(:id)
          session[key] = {
            "token" => token,
            "api_key_id" => api_key_id&.to_s
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
          expected_id = api_key_id || (api_key.id if api_key.respond_to?(:id))

          # Plain string payloads from older versions remain readable only when
          # the caller does not request ID binding.
          return payload if expected_id.nil? && valid_token_payload?(payload)
          return nil unless payload.is_a?(Hash)

          token = payload["token"] || payload[:token]
          stored_id = payload["api_key_id"] || payload[:api_key_id]
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
          expected_id = api_key_id || (api_key.id if api_key.respond_to?(:id))

          return valid_token_payload?(payload) if payload.is_a?(String) && expected_id.nil?
          return false unless payload.is_a?(Hash)

          token = payload["token"] || payload[:token]
          stored_id = payload["api_key_id"] || payload[:api_key_id]
          return false if expected_id && stored_id.to_s != expected_id.to_s

          valid_token_payload?(token)
        end

        private

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
