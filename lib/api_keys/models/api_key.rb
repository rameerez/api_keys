# frozen_string_literal: true

require "active_record"
require_relative "../services/token_generator"
require_relative "../services/digestor"

module ApiKeys
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

    # JSON attributes (:scopes, :metadata) are defined in the engine initializer
    # using ActiveSupport.on_load(:active_record) to ensure DB connection is ready.

    # == Validations ==
    validates :token_digest, presence: true, uniqueness: { case_sensitive: true }
    validates :prefix, presence: true
    validates :digest_algorithm, presence: true
    validates :last4, presence: true, length: { is: 4 }
    # validates :scopes, presence: true # Default handled by attribute def
    # validates :metadata, presence: true # Default handled by attribute def
    validates :name,
              length: { maximum: 60 },
              # Allow letters, numbers, underscores, hyphens. No leading/trailing spaces.
              format: { with: /\A[a-zA-Z0-9_-]+\z/, message: "can only contain letters, numbers, underscores, and hyphens" },
              allow_blank: true # Apply length and format only if name is present

    validates :name, presence: true, if: :name_required? # Only require presence conditionally
    validate :within_quota, on: :create, if: -> { owner.present? && (owner_configured? || ApiKeys.configuration.default_max_keys_per_owner.present?) }

    # TODO: Add validation for expires_at > Time.current if present
    validate :expiration_date_cannot_be_in_the_past, if: :expires_at?

    # TODO: Add validation for scope string format
    # TODO: Add validation for prefix format (e.g., must end with _)

    # == Callbacks ==
    before_validation :set_defaults, on: :create
    # Generate digest BEFORE validation runs
    before_validation :generate_token_and_digest, on: :create

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
      # Type casting for scopes/metadata happens via the attribute definition in the engine.
      # Ensure the attribute is loaded/defined before using it.
      # Check if the attribute method exists before calling .blank? or .include?
      return true unless respond_to?(:scopes) # Guard clause if loaded before attribute definition
      scopes.blank? || scopes.include?(required_scope.to_s)
    end

    # Provides a masked version of the token for display (e.g., ak_live_••••rj4p)
    # Requires the plaintext token to be available (only right after creation).
    def masked_token
      # return "[Token not available]" unless token # No longer needed
      # Show prefix, 4 bullets, last 4 chars of the random part
      # random_part = token.delete_prefix(prefix) # No longer needed
      # "#{prefix}••••#{random_part.last(4)}" # No longer needed

      # Use the stored prefix and last4 attributes
      return "[Invalid Key Data]" unless prefix.present? && last4.present?
      "#{prefix}••••#{last4}"
    end

    # == Class Methods ==
    # Most creation logic is handled by standard ActiveRecord methods + callbacks

    private

    # Set defaults for attributes not handled by the `attribute` API in the engine.
    def set_defaults
      # NOTE: Defaults for scopes/metadata handled by `attribute` definitions in engine initializer.

      # Determine the prefix: owner-specific setting > global config
      # Note: `owner` might not be set yet if called outside normal AR flow.
      owner_prefix_config = nil
      if owner.present? && owner.class.respond_to?(:api_keys_settings)
        owner_prefix_config = owner.class.api_keys_settings[:token_prefix]
      end

      # Use owner setting if present, otherwise fall back to global config
      prefix_config = owner_prefix_config || ApiKeys.configuration.token_prefix

      # Evaluate the prefix config (it might be a Proc)
      # Ensure `self.prefix` is only set if it's not already present.
      self.prefix ||= prefix_config.is_a?(Proc) ? prefix_config.call : prefix_config

      # Removed default scopes logic here. It's correctly handled in the
      # HasApiKeys#create_api_key! helper method, which is the intended
      # way to create keys with proper default scope application.
    end

    # Generates the secure token, hashes it, and sets relevant attributes.
    # Called before validation on create.
    def generate_token_and_digest
      # Generate token only if digest isn't already set (allows creating records with pre-hashed keys if needed)
      return if token_digest.present?

      # Ensure prefix default is set if needed (e.g., if validation skipped or called directly)
      set_defaults unless self.prefix.present?

      # Use the configured generator
      generated_token = ApiKeys::Services::TokenGenerator.call(prefix: self.prefix)
      @token = generated_token # Store plaintext temporarily in instance var for display

      # Safety check: Ensure generated token starts with the expected prefix
      unless @token.start_with?(self.prefix)
        raise ApiKeys::Error, "Generated token '#{@token}' does not match expected prefix '#{self.prefix}'. Check TokenGenerator."
      end

      # Use the configured digestor
      digest_result = ApiKeys::Services::Digestor.digest(token: @token)

      self.token_digest = digest_result[:digest]
      self.digest_algorithm = digest_result[:algorithm]

      # Extract and store the last 4 chars of the random part
      random_part = @token.delete_prefix(self.prefix)
      self.last4 = random_part.last(4) # Store last4

      # Set default expiration if configured globally and not set individually
      # Needs to happen here since it relies on Time.current
      if ApiKeys.configuration.expire_after.present? && self.expires_at.nil?
        self.expires_at = ApiKeys.configuration.expire_after.from_now
      end
    end

    # == Validation Helpers ==

    def owner_present_and_configured?
      owner.present? && owner_configured?
    end

    def owner_configured?
      owner.class.respond_to?(:api_keys_settings)
    end

    def name_required?
      if owner_configured?
        owner.class.api_keys_settings[:require_name]
      else
        ApiKeys.configuration.require_key_name
      end
    end

    def within_quota
      # Determine the applicable limit: owner-specific setting first, then global config.
      limit = if owner_configured?
                owner.class.api_keys_settings[:max_keys]
              else
                ApiKeys.configuration.default_max_keys_per_owner
              end

      # Only validate if a limit is actually set (either per-owner or globally).
      return unless limit.present?

      # Count only *active* keys for the quota check.
      # Ensure `owner` association is loaded if needed, or use SQL count.
      # Note: Ensure the owner association is set before this validation runs.
      current_active_keys = owner.api_keys.active.count

      if current_active_keys >= limit
        errors.add(:base, "exceeds maximum allowed API keys (#{limit}) for this owner")
      end
    end

    def expiration_date_cannot_be_in_the_past
      errors.add(:expires_at, "can't be in the past") if expires_at.present? && expires_at < Time.current
    end

  end
end
