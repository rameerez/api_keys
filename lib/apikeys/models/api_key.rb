# frozen_string_literal: true

require "active_record"
require_relative "../services/token_generator"
require_relative "../services/digestor"

module Apikeys
  # The core ActiveRecord model representing an API key.
  class ApiKey < ActiveRecord::Base
    self.table_name = "api_keys"

    # == Concerns ==
    # TODO: Potentially extract token generation/hashing logic into concerns

    # == Associations ==
    belongs_to :owner, polymorphic: true, optional: true

    # == Attributes & Serialization ==
    # Expose the plaintext token only immediately after creation
    attr_reader :token

    # Serialize `scopes` and `metadata` as JSON(B)
    # Use json for broader DB compatibility (SQLite, MySQL), jsonb preferred for PG
    # TODO: Consider making the column type configurable or detecting PG
    serialize :scopes
    serialize :metadata

    # == Validations ==
    validates :token_digest, presence: true, uniqueness: { case_sensitive: true }
    validates :prefix, presence: true
    validates :digest_algorithm, presence: true
    validates :scopes, presence: true
    validates :metadata, presence: true
    validates :name, presence: true, if: :name_required?
    validate :within_quota, on: :create, if: :owner_present_and_configured?

    # TODO: Add validation for expires_at > Time.current if present
    validate :expiration_date_cannot_be_in_the_past, if: :expires_at?

    # TODO: Add validation for scope string format
    # TODO: Add validation for prefix format (e.g., must end with _)

    # == Callbacks ==
    before_validation :set_defaults, on: :create
    before_create :generate_token_and_digest

    # == Scopes ==
    scope :active, -> { where(revoked_at: nil).where("expires_at IS NULL OR expires_at > ?", Time.current) }
    scope :revoked, -> { where.not(revoked_at: nil) }
    scope :expired, -> { where("expires_at <= ?", Time.current) }
    scope :inactive, -> { revoked.or(expired) }
    scope :for_prefix, ->(prefix) { where(prefix: prefix) }
    scope :for_owner, ->(owner) { where(owner: owner) }
    # TODO: Add more scopes as needed (e.g., for_owner)

    # == Instance Methods ==

    def revoke!
      update!(revoked_at: Time.current)
    end

    def revoked?
      revoked_at.present?
    end

    def expired?
      expires_at? && expires_at <= Time.current
    end

    def active?
      !revoked? && !expired?
    end

    # Basic scope check. Assumes scopes are stored as an array of strings.
    # Returns true if the key has no specific scopes (allowing all) or includes the required scope.
    def allows_scope?(required_scope)
      scopes.blank? || scopes.include?(required_scope.to_s)
    end

    # Provides a masked version of the token for display (e.g., ak_live_••••rj4p)
    # Requires the plaintext token to be available (only right after creation).
    def masked_token
      return "[Token not available]" unless token
      # Show prefix, 4 bullets, last 4 chars of the random part
      random_part = token.delete_prefix(prefix)
      "#{prefix}••••#{random_part.last(4)}"
    end

    # == Class Methods ==
    # Most creation logic is handled by standard ActiveRecord methods + callbacks

    private

    def set_defaults
      # Use owner-specific defaults if available, else global config
      owner_settings = owner.class.apikeys_settings if owner_configured?
      self.scopes ||= (owner_settings&.[](:default_scopes) || Apikeys.configuration.default_scopes || [])
      self.metadata ||= {}
      self.prefix ||= Apikeys.configuration.token_prefix.call
    end

    # Generates the secure token, hashes it, and sets relevant attributes.
    # This is the core security mechanism.
    def generate_token_and_digest
      # Generate token only if digest isn't already set (allows creating records with pre-hashed keys if needed)
      return if token_digest.present?

      # Use the configured generator
      generated_token = Apikeys::Services::TokenGenerator.call(prefix: self.prefix)
      @token = generated_token # Store plaintext temporarily in instance var for display

      # Safety check: Ensure generated token starts with the expected prefix
      unless @token.start_with?(self.prefix)
        raise Apikeys::Error, "Generated token '#{@token}' does not match expected prefix '#{self.prefix}'. Check TokenGenerator."
      end

      # Use the configured digestor
      digest_result = Apikeys::Services::Digestor.digest(token: @token)

      self.token_digest = digest_result[:digest]
      self.digest_algorithm = digest_result[:algorithm]

      # Set default expiration if configured globally and not set individually
      if Apikeys.configuration.expire_after.present? && self.expires_at.nil?
        self.expires_at = Apikeys.configuration.expire_after.from_now
      end
    end

    # == Validation Helpers ==

    def owner_present_and_configured?
      owner.present? && owner_configured?
    end

    def owner_configured?
      owner.class.respond_to?(:apikeys_settings)
    end

    def name_required?
      if owner_configured?
        owner.class.apikeys_settings[:require_name]
      else
        Apikeys.configuration.require_key_name
      end
    end

    def within_quota
      owner_settings = owner.class.apikeys_settings
      return unless owner_settings && owner_settings[:max_keys].present?

      # Count only *active* keys for the quota check
      current_active_keys = owner.api_keys.active.count
      if current_active_keys >= owner_settings[:max_keys]
        errors.add(:base, "exceeds maximum allowed API keys (#{owner_settings[:max_keys]}) for this owner")
      end
    end

    def expiration_date_cannot_be_in_the_past
      errors.add(:expires_at, "can't be in the past") if expires_at < Time.current
    end
  end
end
