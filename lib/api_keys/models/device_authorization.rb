# frozen_string_literal: true

require "active_record"
require "digest"
require "securerandom"

module ApiKeys
  # A client's request for an API key on the OAuth 2.0 Device Authorization
  # Grant (RFC 8628, https://www.rfc-editor.org/rfc/rfc8628):
  #
  #   1. The client (an agent, a CLI) asks for a device code and a user code
  #      and shows the person one link (`request!`, RFC 8628 §3.1, §3.2).
  #   2. The person opens the link in the host app, compares the user code,
  #      sees the client's name, its device and the scopes, and approves or
  #      denies (`approve!`, `deny!`, §3.3).
  #   3. The client polls. The first poll after the approval creates an
  #      ordinary API key for the owner and answers with its token, once
  #      (`poll!`, §3.4, §3.5).
  #
  # Both codes are kept as SHA-256 digests. The token is never stored: the
  # poll that creates the key is the only answer that carries its text.
  class DeviceAuthorization < ActiveRecord::Base
    self.table_name = "api_keys_device_authorizations"

    LIFETIME = 10.minutes
    INTERVAL = 5 # seconds between polls: the RFC 8628 §3.2 default
    SLOW_DOWN = 5 # "the interval MUST be increased by 5 seconds" (§3.5)
    # Eight letters from twenty consonants: about 34.5 bits, and no word can
    # be spelled (§6.1). Shown as BCDF-GHJK.
    USER_CODE_ALPHABET = "BCDFGHJKLMNPQRSTVWXZ".chars.freeze
    USER_CODE_LENGTH = 8
    MAX_NAME_LENGTH = 60 # for client_id and device_name each
    STATES = %w[pending approved denied completed].freeze

    # Raised when a request that was decided already, or that expired, is
    # approved or denied.
    class Closed < ApiKeys::Error; end

    # The answer to one poll: the new key, or the RFC 8628 §3.5 error code.
    Poll = Struct.new(:api_key, :error, keyword_init: true)

    belongs_to :owner, polymorphic: true, optional: true
    belongs_to :decided_by, polymorphic: true, optional: true
    belongs_to :api_key, class_name: "ApiKeys::ApiKey", optional: true

    # The plaintext codes, on the instance `request!` returns only.
    attr_reader :device_code, :user_code

    validates :client_id, presence: true, length: { maximum: MAX_NAME_LENGTH }
    validates :device_name, length: { maximum: MAX_NAME_LENGTH }
    validates :state, inclusion: { in: STATES }
    validate :scopes_are_grantable

    scope :undecided, -> { where(state: "pending").where("expires_at > ?", Time.current) }

    STATES.each { |state| define_method(:"#{state}?") { self.state == state } }

    class << self
      # A new request. Its `device_code` and `user_code` hold the plaintext
      # codes on this instance only.
      #
      # @return [ApiKeys::DeviceAuthorization]
      # @raise [ActiveRecord::RecordInvalid] for a missing client_id, a name
      #   that is too long, or scopes the app does not grant
      def request!(client_id:, scopes:, device_name: nil, requested_from: nil)
        device_code = SecureRandom.urlsafe_base64(32)
        user_code = Array.new(USER_CODE_LENGTH) { USER_CODE_ALPHABET[SecureRandom.random_number(USER_CODE_ALPHABET.size)] }.join
        authorization = create!(
          device_code_digest: digest(device_code), user_code_digest: digest(user_code),
          client_id: client_id, device_name: device_name, scopes: Array(scopes).uniq,
          requested_from: requested_from, interval: INTERVAL, expires_at: LIFETIME.from_now
        )
        authorization.instance_variable_set(:@device_code, device_code)
        authorization.instance_variable_set(:@user_code, user_code.scan(/.{4}/).join("-"))
        authorization
      end

      # The undecided request whose user code a person typed or followed.
      # Case, spaces and dashes do not matter (§6.1).
      def find_undecided_by_user_code(code)
        undecided.find_by(user_code_digest: digest(code.to_s.upcase.gsub(/[^A-Z]/, "")))
      end

      def find_by_device_code(code)
        find_by(device_code_digest: digest(code.to_s))
      end

      # The scopes a client may ask for: the app's `config.default_scopes`,
      # the scopes a person can give a key.
      def grantable_scopes
        ApiKeys.configuration.default_scopes
      end

      def digest(text)
        Digest::SHA256.hexdigest(text)
      end

      # Deletes the requests that expired more than a day ago.
      # @return [Integer] How many were deleted.
      def prune!
        where(expires_at: ...1.day.ago).delete_all
      end
    end

    # The poll names the client that asked (RFC 8628 §3.4). A public client
    # ID is not a secret, but a poll from another client must not get the
    # grant of this one.
    def client?(id)
      client_id == id.to_s.strip
    end

    # "Fictional agent on build-box": the name the key gets. Characters a
    # key name cannot hold become hyphens, so every request can become a key.
    def key_name
      name = [client_id, device_name.presence].compact.join(" on ")
      name.gsub(/[^a-zA-Z0-9_ -]/, "-").squeeze("-").first(ApiKeys::ApiKey::MAX_NAME_LENGTH).strip
    end

    # The person approves for +owner+, a record with `has_api_keys`. The key
    # is created at the next poll (`poll!`), so its token is never stored.
    #
    # @raise [Closed] if the request was decided already or expired
    def approve!(owner, by:)
      unless owner.respond_to?(:create_api_key!) && owner.persisted?
        raise ArgumentError, "approve a device authorization for a saved record that has_api_keys"
      end

      decide!("approved", by: by, owner: owner)
    end

    # @raise [Closed] if the request was decided already or expired
    def deny!(by:)
      decide!("denied", by: by)
    end

    # One poll of the client (§3.4, §3.5), under the row's lock. A poll from
    # another client changes nothing. A poll that comes sooner than the
    # interval slows the client down by five seconds.
    #
    # @return [Poll] the new key once, or the error code
    def poll!(client_id:)
      return Poll.new(error: "invalid_grant") unless client?(client_id)

      with_row_lock do
        next Poll.new(error: "expired_token") if expires_at.past?
        # An owner deleted since the approval gets no key.
        next Poll.new(error: "access_denied") if denied? || (approved? && owner.nil?)
        next Poll.new(error: "invalid_grant") if completed? # the device code was used
        next Poll.new(api_key: complete!) if approved?

        too_soon = last_polled_at && last_polled_at > interval.seconds.ago
        update!(last_polled_at: Time.current, interval: too_soon ? interval + SLOW_DOWN : interval)
        Poll.new(error: too_soon ? "slow_down" : "authorization_pending")
      end
    end

    private

    # A decided or expired request cannot be decided again. The row lock
    # makes two decisions, or a decision and a poll, take turns.
    def decide!(state, by:, owner: nil)
      with_row_lock do
        raise Closed, "this device authorization is no longer open" unless pending? && expires_at.future?

        update!(state: state, owner: owner, decided_by: by, decided_at: Time.current)
      end
    end

    # Reloads the row under its lock for the rest of a transaction. SELECT
    # ... FOR UPDATE locks the row on PostgreSQL and MySQL. SQLite has no
    # row locks, so there an UPDATE first takes the database's write lock,
    # which Rails before 8.0 does not take at BEGIN.
    def with_row_lock
      transaction do
        self.class.where(id: id).update_all(updated_at: Time.current) if self.class.connection.adapter_name.match?(/sqlite/i)
        lock!
        yield
      end
    end

    # The person who approved stands behind the key (created_by), when the
    # api_keys table has the created_by columns.
    def complete!
      person = { created_by: decided_by } if decided_by && ApiKeys::ApiKey.created_by_columns?
      key = owner.create_api_key!(name: key_name, scopes: scopes, **person.to_h)
      update!(state: "completed", api_key: key)
      key
    end

    def scopes_are_grantable
      grantable = self.class.grantable_scopes
      return if scopes.is_a?(Array) && scopes.any? && scopes.all? { |scope| grantable.include?(scope) }

      errors.add(:scopes, :inclusion)
    end
  end
end
