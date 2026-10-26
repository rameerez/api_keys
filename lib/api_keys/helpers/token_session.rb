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
    # it. Two more layers make retrieval one-time across copies:
    #
    # 1. Durable (0.6.0): the first retrieval of a key's handoff claims the
    #    key's `token_shown_at` column with one conditional UPDATE
    #    (`... WHERE id = ? AND token_shown_at IS NULL`). The database makes
    #    exactly one claim succeed, and a cache flush cannot undo it. Zero rows
    #    changed (already shown, or the key is gone) returns nil. Installations
    #    without the column skip this layer and behave as 0.5.1.
    #
    #    The claim is only durable once it commits, so it must run outside any
    #    database transaction: the plaintext is returned before an enclosing
    #    transaction could roll the claim back. A retrieval attempted inside an
    #    open transaction on the ApiKey connection is therefore refused,
    #    whatever the cache: it withholds the token with `:inside_transaction`,
    #    records nothing, and leaves the handoff in the session, so the host
    #    can retrieve it again outside the transaction. The check is Active
    #    Record's transaction manager on that connection, so a transaction
    #    opened with raw SQL (`BEGIN`) is not detected. The dashboard opens no
    #    transaction itself; a host `around_action` that wraps its requests in
    #    one sees the refusal.
    #
    #    The transaction that a transactional test opens around each test does
    #    not count (0.8.1): when Rails.env is test and the only open
    #    transaction is an outer, non-joinable one, the claim runs in it. The
    #    first retrieval in the test returns the token and a second one does
    #    not, as in production. A transaction opened on top of it is refused.
    # 2. Cache marker (0.5.1): each handoff has a random ID, and retrieval
    #    records it in `Rails.cache` with `write(..., unless_exist: true)`;
    #    a later retrieval of the same handoff finds the marker and gets nil.
    #    With the column it is a second layer (it also covers handoffs that
    #    name no key); without it, it is the only one, and it needs a cache
    #    store every process shares, with an atomic `unless_exist:`, that
    #    keeps the marker for the handoff lifetime. With
    #    `ActiveSupport::Cache::NullStore` the marker cannot be recorded.
    #
    # Any failure in either layer withholds the token (fail closed).
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

      # The outcome of `retrieve_once_with_status`. `token` is set only when
      # `status` is `:retrieved`. The other statuses are:
      # - `:already_shown`: an authentic handoff for this key whose token an
      #   earlier retrieval already released (a replayed copy of the session).
      # - `:withheld`: the database or cache could not record the retrieval,
      #   so the token is withheld rather than risk a second release.
      # - `:inside_transaction`: retrieval ran inside an open Active Record
      #   transaction on the ApiKey connection, where its one-time claim could
      #   be rolled back after the token was shown. The token is withheld,
      #   nothing is recorded, and the handoff stays in the session for a
      #   retry outside the transaction. The transaction of a transactional
      #   test does not count; one opened on top of it does.
      # - `:missing`: no usable handoff for this key (none stored, expired,
      #   tampered, or bound to another key).
      #
      # Inspection never prints the token.
      Retrieval = Struct.new(:token, :status) do
        def retrieved?
          status == :retrieved
        end

        def already_shown?
          status == :already_shown
        end

        # Struct's default inspection, string, pretty-print and JSON forms
        # would all print the plaintext token; these say only whether there
        # is one. Read it through #token.
        def inspect
          "#<#{self.class.name} status=#{status.inspect} token=#{token.nil? ? 'nil' : '[REDACTED]'}>"
        end

        alias_method :to_s, :inspect

        def pretty_print(printer)
          printer.text(inspect)
        end

        def as_json(*)
          { "status" => status.to_s, "token" => (token.nil? ? nil : "[REDACTED]") }
        end
      end
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
          retrieve_once_with_status(session, key: key, api_key: api_key, api_key_id: api_key_id).token
        end

        # Same as `retrieve_once`, and also says why no token came back, so a
        # page can tell a replayed handoff ("already shown") from a missing
        # one. The token is consumed exactly as `retrieve_once` consumes it.
        #
        # @return [Retrieval]
        def retrieve_once_with_status(session, key: DEFAULT_SESSION_KEY, api_key: nil, api_key_id: nil)
          payload = session.delete(key)
          expected_id = normalize_api_key_id(api_key_id || (api_key.id if api_key.respond_to?(:id)))

          # Plain string payloads from older versions remain readable only when
          # the caller does not request ID binding.
          return Retrieval.new(payload, :retrieved).freeze if expected_id.nil? && valid_token_payload?(payload)
          decoded_payload = decode_payload(payload)
          return Retrieval.new(nil, :missing).freeze unless decoded_payload

          token = decoded_payload["token"] || decoded_payload[:token]
          stored_id = decoded_payload["api_key_id"] || decoded_payload[:api_key_id]
          bound_elsewhere = expected_id && stored_id.to_s != expected_id.to_s

          # Any authentic retrieval attempt uses the handoff up, matching the
          # session deletion above: a mismatched or replayed attempt never
          # leaves the handoff available to a later one.
          status = consume_handoff(decoded_payload)

          # A handoff bound to another key says nothing about this one.
          return Retrieval.new(nil, :missing).freeze if bound_elsewhere

          if status == :inside_transaction
            # Nothing was recorded, so the handoff goes back into the session
            # and a retrieval outside the transaction can still release it.
            session[key] = payload
            return Retrieval.new(nil, :inside_transaction).freeze
          end
          return Retrieval.new(nil, status).freeze unless status == :consumed
          return Retrieval.new(nil, :missing).freeze unless valid_token_payload?(token)

          Retrieval.new(token, :retrieved).freeze
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

        # Uses the handoff up, durably first and then in the cache. Answers
        # :consumed only to the first consumer of a handoff; a later one gets
        # :already_shown, and any failure :withheld (fail closed).
        def consume_handoff(decoded_payload)
          stored_id = decoded_payload["api_key_id"]
          return refuse_inside_transaction(stored_id) if claim_could_roll_back?(stored_id)

          durable = claim_durably(decoded_payload)
          return durable unless durable.nil? || durable == :consumed

          consume_cache_marker(decoded_payload)
        rescue StandardError => error
          log_warn "[ApiKeys Security] Token handoff could not be checked against the database (#{error.class}); withholding the token."
          :withheld
        end

        # Whether this handoff has a durable claim that an open transaction on
        # the api_keys connection could roll back after the token was shown.
        # Raises on database errors (the caller withholds the token).
        def claim_could_roll_back?(stored_id)
          return false if stored_id.nil? || !defined?(::ApiKeys::ApiKey)
          return false unless ::ApiKeys::ApiKey.column_names.include?(::ApiKeys::ApiKey::TOKEN_SHOWN_AT_COLUMN)

          ::ApiKeys::ApiKey.connection_pool.with_connection do |connection|
            connection.transaction_open? && !only_test_transaction_open?(connection)
          end
        end

        # Whether the only open transaction on +connection+ is the one a
        # transactional test opens around each test. Rails' transactional
        # tests (and rspec-rails, and DatabaseCleaner's :transaction strategy)
        # open it as one outer, non-joinable transaction, and a system test's
        # server thread shares it. A claim in it is as durable as every other
        # write of the test: the test sees it, a second retrieval in the same
        # test is refused, and the rollback at the end of the test removes the
        # key with it. A transaction that the app or the test opens on top of
        # it still refuses the retrieval, as in production.
        #
        # The check reads the shape of the transaction, not where it came
        # from, so three cases follow:
        # - In a test without a transaction of its own, an outer
        #   `transaction(joinable: false)` that the app opens is exempt too.
        #   Production refuses it.
        # - An environment with another name (`ci`, `staging`) is never
        #   exempt: only Rails.env test is.
        # - A test transaction inside another one (fixtures and
        #   DatabaseCleaner's :transaction strategy together) is two deep, so
        #   it is not exempt, as in 0.8.0.
        def only_test_transaction_open?(connection)
          return false unless ApiKeys.test_environment?
          return false unless connection.open_transactions == 1

          !connection.current_transaction.joinable?
        end

        # Inside a transaction the claim is not durable until the host commits,
        # and the token would be returned before that. No cache can stand in
        # for it: a process-local store protects one process, and after a
        # rollback another process would release the token again. So the
        # retrieval is refused and records nothing (no claim, no marker). Only
        # a read tells an already-used handoff apart, which is not put back.
        def refuse_inside_transaction(stored_id)
          return :already_shown if ::ApiKeys::ApiKey.token_handoff_claimable?(stored_id) == false

          log_warn "[ApiKeys Security] Token handoff retrieval ran inside an open database transaction, where its " \
                   "one-time claim could be rolled back; withholding the token and leaving the handoff in place. " \
                   "Retrieve it outside the transaction."
          :inside_transaction
        end

        # The durable layer: the key's `token_shown_at`, claimed by one
        # conditional UPDATE. nil when there is no durable layer for this
        # handoff (the column does not exist yet, or the handoff names no key).
        def claim_durably(decoded_payload)
          stored_id = decoded_payload["api_key_id"]
          return nil if stored_id.nil? || !defined?(::ApiKeys::ApiKey)

          case ::ApiKeys::ApiKey.claim_token_handoff!(stored_id)
          when nil then nil
          when true then :consumed
          else :already_shown
          end
        rescue StandardError => error
          log_warn "[ApiKeys Security] Token handoff could not be recorded in the database (#{error.class}); withholding the token."
          :withheld
        end

        # The cache layer from 0.5.1: an atomic marker named by the handoff ID.
        def consume_cache_marker(decoded_payload)
          cache = consumption_cache
          return :consumed unless cache

          marker = consumption_marker_key(decoded_payload)
          return :consumed unless marker
          return :consumed if cache.write(marker, true, unless_exist: true, expires_in: HANDOFF_TTL)

          # Refused: normally the marker is already there (a replay), but some
          # stores also answer false on error, so only a marker that is
          # really present counts as "already shown".
          cache.exist?(marker) ? :already_shown : :withheld
        rescue StandardError => error
          log_warn "[ApiKeys Security] Token handoff consumption could not be recorded (#{error.class}); withholding the token."
          :withheld
        end

        # Read-only: whether either layer says the handoff was used up. A
        # failed check reads as consumed (fail closed).
        def handoff_consumed?(decoded_payload)
          durably_consumed?(decoded_payload) || cache_marker_present?(decoded_payload)
        end

        def durably_consumed?(decoded_payload)
          stored_id = decoded_payload["api_key_id"]
          return false if stored_id.nil? || !defined?(::ApiKeys::ApiKey)

          ::ApiKeys::ApiKey.token_handoff_claimable?(stored_id) == false
        rescue StandardError => error
          log_warn "[ApiKeys Security] Token handoff consumption could not be checked in the database (#{error.class})."
          true
        end

        def cache_marker_present?(decoded_payload)
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
