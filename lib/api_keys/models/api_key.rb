# frozen_string_literal: true

require "active_record"
require "json"
require_relative "../services/token_generator"
require_relative "../services/digestor"

module ApiKeys
  # The core ActiveRecord model representing an API key.
  class ApiKey < ActiveRecord::Base
    MAX_SCOPES = 100
    MAX_SCOPE_BYTESIZE = 128
    MAX_METADATA_BYTESIZE = 16_384
    IMMUTABLE_IDENTITY_ATTRIBUTES = %w[
      token_digest digest_algorithm prefix last4 owner_type owner_id key_type environment
    ].freeze

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

    # Override scopes setter to auto-clean blank values.
    # This handles the common case where form checkboxes submit empty strings.
    # Works for both create and update operations.
    def scopes=(value)
      cleaned = if value.is_a?(Array)
                  value
                    .map { |scope| scope.is_a?(Symbol) ? scope.to_s : scope }
                    .reject { |scope| scope.respond_to?(:blank?) && scope.blank? }
                    .uniq
                else
                  value
                end
      super(cleaned)
    end

    # == Validations ==
    validates :token_digest, presence: true, uniqueness: { case_sensitive: true }
    validates :prefix, presence: true, length: { maximum: 64 }
    validates :digest_algorithm, presence: true, inclusion: { in: %w[sha256 bcrypt] }
    validates :last4, presence: true, length: { is: 4 }
    # validates :scopes, presence: true # Default handled by attribute def
    # validates :metadata, presence: true # Default handled by attribute def
    validates :name,
              length: { maximum: 60 },
              # Allow letters, numbers, underscores, hyphens, and spaces. No leading/trailing spaces.
              format: { with: /\A[a-zA-Z0-9_ -]+\z/, message: "can only contain letters, numbers, underscores, hyphens, and spaces (no leading / trailing spaces)" },
              allow_blank: true # Apply length and format only if name is present

    validates :name, presence: true, if: :name_required? # Only require presence conditionally
    validate :within_quota, on: :create, if: -> { owner.present? && (owner_configured? || ApiKeys.configuration.default_max_keys_per_owner.present?) }

    # TODO: Add validation for expires_at > Time.current if present
    validate :expiration_date_cannot_be_in_the_past, if: :expires_at?
    validate :within_key_type_limit, on: :create, if: -> { key_type.present? && owner.present? }
    validate :non_revocable_keys_cannot_expire, if: -> { key_type.present? && expires_at.present? }
    validate :scopes_are_well_formed
    validate :scopes_respect_permission_ceiling
    validate :key_type_present_when_feature_enabled, on: :create
    validate :key_type_is_configured, if: -> { key_type.present? }
    validate :environment_is_configured, if: -> { key_type.present? }
    validate :token_digest_matches_algorithm
    validate :token_identifiers_are_well_formed
    validate :metadata_is_well_formed
    validate :authentication_identity_is_immutable, on: :update

    # TODO: Add validation for scope string format
    # TODO: Add validation for prefix format (e.g., must end with _)

    # == Callbacks ==
    before_validation :set_defaults, on: :create
    # Generate digest BEFORE validation runs
    before_validation :generate_token_and_digest, on: :create
    # Serialize quota validation and insertion for every creation path, including
    # direct ApiKey.create! calls that do not use HasApiKeys#create_api_key!.
    before_validation :lock_owner_for_creation, on: :create
    after_commit :clear_known_prefixes_cache, on: :create

    # == Scopes ==
    scope :active, -> { where(revoked_at: nil).where("expires_at IS NULL OR expires_at > ?", Time.current) }
    scope :revoked, -> { where.not(revoked_at: nil) }
    scope :expired, -> { where("expires_at <= ?", Time.current) }
    scope :inactive, -> { revoked.or(expired) }
    scope :for_prefix, ->(prefix) { where(prefix: prefix) }
    scope :for_owner, ->(owner) { where(owner: owner) }
    scope :for_key_type, ->(key_type) { where(key_type: key_type.to_s) }
    scope :for_environment, ->(environment) { where(environment: environment.to_s) }

    # Convenience scopes for key types
    # .publishable returns only keys with key_type: "publishable"
    # .secret returns keys that are NOT publishable (includes legacy keys with nil/blank key_type)
    scope :publishable, -> { where(key_type: "publishable") }
    scope :secret, -> { where.not(key_type: "publishable") }

    # === Usage Analytics Scopes ===
    # These scopes help admin dashboards analyze API key usage patterns.
    # Useful for identifying unused keys, high-traffic keys, and stale keys that may need cleanup.

    # Keys that have never been used (last_used_at is nil)
    scope :never_used, -> { where(last_used_at: nil) }

    # Keys that have been used at least once
    scope :used, -> { where.not(last_used_at: nil) }

    # Order by usage count (highest first) - useful for finding most active keys
    scope :by_requests, -> { order(requests_count: :desc) }

    # Order by last used time (most recent first, nulls last)
    # Uses NULLS LAST for PostgreSQL compatibility; SQLite sorts nulls last by default with DESC
    scope :by_last_used, -> { order(Arel.sql("CASE WHEN last_used_at IS NULL THEN 1 ELSE 0 END, last_used_at DESC")) }

    # Active keys that haven't been used within the specified period.
    # Useful for identifying keys that may have been abandoned or forgotten.
    # Excludes revoked/expired keys since those are already inactive.
    # @param period [ActiveSupport::Duration] The inactivity threshold (default: 30 days)
    scope :stale, ->(period = 30.days) {
      active.where("last_used_at < :threshold OR last_used_at IS NULL", threshold: period.ago)
    }

    # Aliases for common admin dashboard naming conventions
    class << self
      alias_method :most_used, :by_requests
      alias_method :recently_used, :by_last_used
    end

    # Convenience scope for 30-day stale keys (common admin filter)
    scope :inactive_for_30_days, -> { stale(30.days) }

    # == Instance Methods ==

    def revoke!
      raise ApiKeys::Errors::KeyNotRevocableError unless revocable?
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

    # The plaintext token is an ephemeral creation-time value. Active Record's
    # reload does not clear arbitrary instance variables, so clear it explicitly.
    def reload(...)
      @token = nil
      super
    end

    # Keep credentials and credential-derived values out of logs and consoles.
    def inspect
      attributes = %w[id prefix last4 name owner_type owner_id key_type environment expires_at revoked_at]
                   .select { |attribute_name| has_attribute?(attribute_name) }
                   .map { |attribute_name| "#{attribute_name}: #{attribute_for_inspect(attribute_name)}" }
      "#<#{self.class.name} #{attributes.join(', ')}>"
    rescue StandardError
      "#<#{self.class.name}>"
    end

    def pretty_print(printer)
      printer.text(inspect)
    end

    # Rendering a model as JSON must never expose the verification digest or a
    # public token stored in the reserved metadata field. Call #viewable_token
    # explicitly when an authenticated UI intentionally needs a public token.
    def serializable_hash(options = nil)
      serialized = super(options)
      serialized.delete("token_digest")
      serialized.delete(:token_digest)

      metadata_value = serialized["metadata"] || serialized[:metadata]
      if metadata_value.is_a?(Hash)
        sanitized_metadata = metadata_value.dup
        sanitized_metadata.delete("token")
        sanitized_metadata.delete(:token)
        serialized[serialized.key?("metadata") ? "metadata" : :metadata] = sanitized_metadata
      end

      serialized
    end

    # Returns true if this key can be revoked/destroyed
    # Keys without a key_type (legacy) are always revocable
    # Keys with a key_type check the configuration
    def revocable?
      return true if key_type.blank?
      config = key_type_config
      return false if config.nil?
      config.fetch(:revocable, true)
    end

    # Returns the configuration hash for this key's type
    def key_type_config
      return nil if key_type.blank?
      configured_pair = ApiKeys.configuration.key_types&.find { |type, _settings| type.to_s == key_type.to_s }
      configured_pair&.last
    end

    # Returns the configuration hash for this key's environment
    def environment_config
      return nil if environment.blank?
      configured_pair = ApiKeys.configuration.environments&.find { |name, _settings| name.to_s == environment.to_s }
      configured_pair&.last
    end

    # Returns true if this key type is configured as public AND non-revocable.
    # Only these keys have their plaintext token stored in metadata for later viewing.
    # This is used for publishable keys that are designed to be embedded in distributed apps.
    def public_key_type?
      return false if key_type.blank?
      config = key_type_config
      return false if config.nil?
      config[:public] == true && config[:revocable] == false
    end

    # Returns the stored plaintext token for public, non-revocable keys.
    # Returns nil for all other key types (the token is only available at creation time).
    # @return [String, nil] The full plaintext token, or nil if not stored
    def viewable_token
      return nil unless public_key_type?
      metadata&.dig("token")
    end

    # Override destroy to prevent destroying non-revocable keys
    def destroy
      raise ApiKeys::Errors::KeyNotRevocableError unless revocable?
      super
    end

    def destroy!
      raise ApiKeys::Errors::KeyNotRevocableError unless revocable?
      super
    end

    # Basic scope check. Assumes scopes are stored as an array of strings.
    #
    # Behavior depends on whether key_types mode is enabled:
    # - Simple mode (no key_types): blank scopes means "unrestricted" (all scopes allowed).
    #   This preserves backwards compatibility for apps that don't use scopes at all.
    # - Key types mode: blank scopes means "no permissions". When you've configured
    #   key types with permission ceilings, an empty scope list should deny access,
    #   not silently bypass the entire permission system.
    def allows_scope?(required_scope)
      return false unless respond_to?(:scopes)
      return false unless required_scope.present?
      return false unless scopes.is_a?(Array)

      if scopes.blank?
        return !scope_policy_enabled?
      end

      required = required_scope.to_s
      return false unless scopes.all? { |scope| valid_scope_value?(scope) }
      return false unless scopes.include?(required)

      ceiling = permission_ceiling
      ceiling == :all || ceiling.include?(required)
    end

    # Alias for scopes - provides a more user-friendly API that matches
    # the configuration DSL where key types use `permissions` for scope ceiling.
    # Note: We use a method instead of alias_method because `scopes` is defined
    # dynamically via the `attribute` API in the engine initializer.
    # @return [Array<String>] The permissions (scopes) assigned to this key
    def permissions
      scopes
    end

    # Check if this key has a specific permission (alias for allows_scope?)
    # @param required_permission [String, Symbol] The permission to check
    # @return [Boolean] true if the key has this permission or has no restrictions
    def allows_permission?(required_permission)
      allows_scope?(required_permission)
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

      # If key_types feature is enabled (non-empty key_types config), use type+env prefix
      if key_types_feature_enabled? && key_type.present?
        self.prefix ||= build_typed_prefix
      else
        # Legacy behavior: use owner-specific or global config prefix
        owner_prefix_config = nil
        if owner.present? && owner.class.respond_to?(:api_keys_settings)
          owner_prefix_config = owner.class.api_keys_settings[:token_prefix]
        end

        # Use owner setting if present, otherwise fall back to global config
        prefix_config = owner_prefix_config || ApiKeys.configuration.token_prefix

        # Evaluate the prefix config (it might be a Proc)
        self.prefix ||= prefix_config.is_a?(Proc) ? prefix_config.call : prefix_config
      end

      # Removed default scopes logic here. It's correctly handled in the
      # HasApiKeys#create_api_key! helper method, which is the intended
      # way to create keys with proper default scope application.
    end

    # Build prefix from key_type and environment configuration
    # e.g., publishable + test → "pk_test_"
    def build_typed_prefix
      type_config = key_type_config
      env_config = environment_config

      type_prefix = type_config&.dig(:prefix) || key_type.to_s[0..1]
      env_segment = env_config&.dig(:prefix_segment)

      if env_segment.present?
        "#{type_prefix}_#{env_segment}_"
      else
        "#{type_prefix}_"
      end
    end

    # Check if key types feature is enabled
    def key_types_feature_enabled?
      ApiKeys.configuration.key_types.present? && ApiKeys.configuration.key_types.any?
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
        @token = nil
        raise ApiKeys::Error, "Generated token does not match the configured prefix. Check TokenGenerator configuration."
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

      # Store plaintext token in metadata for public, non-revocable keys.
      # This allows users to view the token again in the dashboard.
      # SECURITY: Only do this for keys explicitly configured as public: true
      # AND revocable: false (e.g., publishable keys for distributed apps).
      if public_key_type?
        self.metadata = (self.metadata || {}).merge("token" => @token)
      end
    end

    # == Validation Helpers ==

    def lock_owner_for_creation
      return unless owner&.persisted?

      # Query a separate relation so locking does not reload or discard unsaved
      # attributes on the caller's in-memory owner object. `unscoped` ensures a
      # tenant/default scope cannot accidentally bypass quota serialization.
      owner.class.unscoped.lock(true).find(owner.id)
    end

    def scopes_are_well_formed
      unless scopes.is_a?(Array)
        errors.add(:scopes, "must be an array")
        return
      end

      if scopes.length > MAX_SCOPES
        errors.add(:scopes, "cannot contain more than #{MAX_SCOPES} entries")
      end

      unless scopes.all? { |scope| valid_scope_value?(scope) }
        errors.add(:scopes, "must contain only non-blank strings of at most #{MAX_SCOPE_BYTESIZE} bytes without whitespace or control characters")
      end
    end

    def token_digest_matches_algorithm
      return if token_digest.blank? || digest_algorithm.blank?

      valid = case digest_algorithm.to_s
              when "sha256"
                token_digest.is_a?(String) && token_digest.match?(/\A\h{64}\z/)
              when "bcrypt"
                ApiKeys::Services::Digestor.valid_bcrypt_digest?(token_digest)
              else
                true # The inclusion validation reports unsupported algorithms.
              end
      errors.add(:token_digest, "is not a valid #{digest_algorithm} digest") unless valid
    end

    def token_identifiers_are_well_formed
      unless safe_token_component?(prefix, maximum_bytes: 64)
        errors.add(:prefix, "must not contain whitespace or control characters")
      end
      unless safe_token_component?(last4, maximum_bytes: 4)
        errors.add(:last4, "must not contain whitespace or control characters")
      end

      %i[key_type environment].each do |attribute_name|
        value = public_send(attribute_name)
        next if value.blank?
        next if value.is_a?(String) && value.bytesize <= 64 && value.match?(/\A[a-zA-Z0-9_-]+\z/)

        errors.add(attribute_name, "must contain only letters, numbers, underscores, or hyphens (maximum 64 bytes)")
      end
    end

    def metadata_is_well_formed
      unless metadata.is_a?(Hash)
        errors.add(:metadata, "must be an object")
        return
      end

      errors.add(:metadata, "is too large") if JSON.generate(metadata).bytesize > MAX_METADATA_BYTESIZE
    rescue JSON::GeneratorError, EncodingError
      errors.add(:metadata, "must contain valid JSON data")
    end

    def authentication_identity_is_immutable
      IMMUTABLE_IDENTITY_ATTRIBUTES.each do |attribute_name|
        next unless will_save_change_to_attribute?(attribute_name)

        errors.add(attribute_name, "cannot be changed after creation")
      end
    end

    def scopes_respect_permission_ceiling
      return unless scopes.is_a?(Array)

      ceiling = permission_ceiling
      return if ceiling == :all
      return if scopes.all? { |scope| ceiling.include?(scope) }

      errors.add(:scopes, "exceed the configured permission ceiling")
    end

    def key_type_is_configured
      return if key_type_config

      errors.add(:key_type, "is not configured")
    end

    def key_type_present_when_feature_enabled
      return unless key_types_feature_enabled?
      return if key_type.present?

      errors.add(:key_type, "must be present when key types are configured")
    end

    def environment_is_configured
      if environment.blank?
        errors.add(:environment, "must be present for typed API keys")
        return
      end

      configured_environments = ApiKeys.configuration.environments
      return if configured_environments.blank? || environment_config

      errors.add(:environment, "is not configured")
    end

    def valid_scope_value?(scope)
      scope.is_a?(String) && scope.present? && scope.valid_encoding? &&
        scope.bytesize <= MAX_SCOPE_BYTESIZE &&
        scope.each_codepoint.none? { |codepoint| codepoint <= 0x20 || codepoint == 0x7f }
    rescue ArgumentError
      false
    end

    def safe_token_component?(value, maximum_bytes:)
      value.is_a?(String) && value.present? && value.valid_encoding? && value.bytesize <= maximum_bytes &&
        value.each_codepoint.none? { |codepoint| codepoint <= 0x20 || codepoint == 0x7f }
    rescue ArgumentError
      false
    end

    def permission_ceiling
      if key_type.present?
        config = key_type_config
        return [] unless config

        permissions = config[:permissions]
        return :all if permissions == :all

        return Array(permissions).map(&:to_s)
      end

      configured_simple_scopes = simple_scope_configuration
      configured_simple_scopes.present? ? configured_simple_scopes : :all
    end

    def scope_policy_enabled?
      key_type.present? || ApiKeys.configuration.key_types.present? || simple_scope_configuration.present?
    end

    def simple_scope_configuration
      owner_scopes = if owner&.class.respond_to?(:api_keys_settings)
                       owner.class.api_keys_settings&.[](:default_scopes)
                     end
      configured = owner_scopes.presence || ApiKeys.configuration.default_scopes
      Array(configured).map(&:to_s)
    end

    def clear_known_prefixes_cache
      return unless defined?(ApiKeys::Services::Authenticator)

      ApiKeys::Services::Authenticator.clear_known_prefixes_cache
    end

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

    # Non-revocable keys cannot have expiration dates.
    # If a key expires but cannot be revoked/deleted, the user would be stuck
    # with a useless expired key they can't remove.
    def non_revocable_keys_cannot_expire
      return unless key_type.present? && expires_at.present?

      config = key_type_config
      return unless config # No config = allow (legacy behavior)

      # If this key type is non-revocable, prevent setting expiration
      if config[:revocable] == false
        errors.add(:expires_at, "cannot be set on non-revocable keys (#{key_type} keys cannot be revoked or deleted)")
      end
    end

    # Check if creating this key would exceed the limit for this key type/environment.
    # HasApiKeys#create_api_key! locks the owner row around this validation and insert.
    def within_key_type_limit
      return unless key_types_feature_enabled?

      config = key_type_config
      return unless config # No config = no limit

      limit = config[:limit]
      return unless limit # nil limit = unlimited

      existing_count = owner.api_keys
                            .active
                            .where(key_type: key_type.to_s)
                            .where(environment: environment.to_s)
                            .count

      if existing_count >= limit
        errors.add(:base, "Maximum number of #{key_type} keys (#{limit}) reached for #{environment} environment")
      end
    end

  end
end
