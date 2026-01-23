# frozen_string_literal: true

require "active_support/concern"

module ApiKeys
  module Models
    module Concerns
      # Concern to add API key capabilities to an owner model (e.g., User, Organization).
      # This module provides the `has_api_keys` class method when extended onto ActiveRecord::Base.
      module HasApiKeys
        extend ActiveSupport::Concern

        # Module containing class methods to be extended onto ActiveRecord::Base
        module ClassMethods
          # Defines the association and allows configuration for the specific owner model.
          #
          # Example:
          #   class User < ApplicationRecord
          #     # Using keyword arguments:
          #     has_api_keys max_keys: 5, require_name: true
          #
          #     # Or using a block:
          #     has_api_keys do
          #       max_keys 10
          #       require_name false
          #       default_scopes %w[read write]
          #     end
          #   end
          def has_api_keys(**options, &block)
            # Include the concern's instance methods into the calling class (e.g., User)
            # Ensures any instance-level helpers in HasApiKeys are available on the owner.
            include ApiKeys::Models::Concerns::HasApiKeys unless included_modules.include?(ApiKeys::Models::Concerns::HasApiKeys)

            # Define the core association on the specific class calling this method
            has_many :api_keys,
                     class_name: "ApiKeys::ApiKey",
                     as: :owner,
                     dependent: :destroy # Consider :nullify based on requirements

            # Define class_attribute for settings if not already defined.
            # This ensures inheritance works correctly (subclasses get their own copy).
            unless respond_to?(:api_keys_settings)
              class_attribute :api_keys_settings, instance_writer: false, default: {}
            end

            # Initialize settings for this specific class, merging defaults and options
            current_settings = {
              # Default to global config values first
              max_keys: ApiKeys.configuration&.default_max_keys_per_owner,
              require_name: ApiKeys.configuration&.require_key_name,
              default_scopes: ApiKeys.configuration&.default_scopes || []
            }.merge(options) # Merge keyword arguments first

            # Apply DSL block if provided, allowing overrides
            if block_given?
              dsl = DslProvider.new(current_settings)
              dsl.instance_eval(&block)
            end

            # Assign the final settings hash to the class attribute for this class
            self.api_keys_settings = current_settings

            # TODO: Add validation hook to check key limit on create?
            # validates_with ApiKeys::Validators::MaxKeysValidator, on: :create, if: -> { api_keys_settings[:max_keys].present? }
          end
        end

        # DSL provider class to handle the block configuration
        class DslProvider # Keep nested or move to a separate file if it grows
          def initialize(settings)
            @settings = settings # Operates directly on the hash passed in
          end

          def max_keys(value)
            @settings[:max_keys] = value
          end

          def require_name(value)
            @settings[:require_name] = value
          end

          def default_scopes(value)
            @settings[:default_scopes] = Array(value)
          end

          # Placeholder for future scope definitions
          # def define_scope(name, description:)
          #   # In v1, this might just store metadata for documentation/future use
          #   # Could store in a separate class attribute or within settings hash.
          #   @settings[:defined_scopes] ||= {}
          #   @settings[:defined_scopes][name.to_s] = description
          # end
        end

        # --- Instance Methods ---
        # Methods included in the owner model (e.g., User).

        # Returns the available scopes for API keys on this owner.
        # Uses owner-specific settings if defined, otherwise falls back to global config.
        # Useful for populating scope checkboxes in forms.
        #
        # @return [Array<String>] The available scopes
        def available_api_key_scopes
          owner_settings = self.class.api_keys_settings
          owner_settings&.[](:default_scopes) || ApiKeys.configuration.default_scopes || []
        end

        # Checks if this owner can create an API key of the given type.
        # Returns false if the limit for this key type/environment is reached.
        # Useful for conditional UI (e.g., hiding "Create" button when at limit).
        #
        # @param key_type [Symbol, nil] The key type to check (e.g., :publishable, :secret)
        # @param environment [Symbol, nil] The environment to check (defaults to current_environment)
        # @return [Boolean] true if the owner can create another key of this type
        #
        # @example
        #   if current_org.can_create_api_key?(key_type: :publishable)
        #     # Show "Create Publishable Key" button
        #   end
        #
        def can_create_api_key?(key_type: nil, environment: nil)
          config = ApiKeys.configuration

          # If no key_type specified, check global quota only
          return within_global_quota? if key_type.nil?

          # Resolve environment
          resolved_environment = resolve_environment(environment, key_type, config)

          # Get type-specific limit
          type_config = config.key_types&.dig(key_type.to_sym)
          return within_global_quota? unless type_config

          limit = type_config[:limit]
          return within_global_quota? unless limit

          # Count existing keys of this type/environment
          existing_count = api_keys
                            .active
                            .where(key_type: key_type.to_s)
                            .where(environment: resolved_environment.to_s)
                            .count

          existing_count < limit && within_global_quota?
        end

        # Creates a new API key for this owner instance and returns the ApiKey instance.
        # Raises ActiveRecord::RecordInvalid if creation fails.
        #
        # @param name [String] The name for the new API key (required).
        # @param scopes [Array<String>, nil] Scopes for the key. Defaults to owner/global settings.
        #   When key_type is specified, scopes are filtered to only include those allowed
        #   by the key type's permissions ceiling. Blank values are automatically removed.
        # @param expires_at [Time, nil] Optional expiration timestamp.
        # @param expires_at_preset [String, nil] Convenience param: "7_days", "30_days", "no_expiration", etc.
        #   If provided, this is parsed into expires_at. Takes precedence over expires_at if both given.
        # @param metadata [Hash, nil] Optional metadata hash.
        # @param key_type [Symbol, nil] The key type (e.g., :publishable, :secret).
        #   Must be defined in ApiKeys.configuration.key_types if provided.
        # @param environment [Symbol, nil] The environment (e.g., :test, :live).
        #   Defaults to current_environment if key_types feature is enabled.
        # @return [ApiKeys::ApiKey] The newly created ApiKey instance. The plaintext token
        #                           is available via the `#token` attribute on this instance
        #                           *only until it's reloaded*.
        def create_api_key!(name: nil, scopes: nil, expires_at: nil, expires_at_preset: nil, metadata: nil, key_type: nil, environment: nil)
          config = ApiKeys.configuration

          # Parse expires_at_preset if provided (takes precedence over expires_at)
          if expires_at_preset.present?
            expires_at = ApiKeys::Helpers::ExpirationOptions.parse(expires_at_preset)
          end

          # Auto-clean scopes: remove blank values from arrays (common when using form checkboxes)
          if scopes.is_a?(Array)
            scopes = scopes.reject { |s| s.blank? }
          end

          # Check for missing columns if key_types feature is enabled
          if key_types_feature_enabled?(config)
            check_required_columns!
          end

          # Use default_key_type if not specified and key_types feature is enabled
          resolved_key_type = key_type
          if resolved_key_type.nil? && key_types_feature_enabled?(config) && config.default_key_type.present?
            resolved_key_type = config.default_key_type
          end

          # Validate key_type if provided and key_types feature is enabled
          if resolved_key_type.present?
            validate_key_type!(resolved_key_type, config)
          end

          # Determine environment: use provided, or default from config
          resolved_environment = resolve_environment(environment, resolved_key_type, config)

          # Validate environment if key_types feature is enabled
          if resolved_environment.present? && key_types_feature_enabled?(config)
            validate_environment!(resolved_environment, config)
          end

          # Fetch default scopes from this owner class's settings, falling back to global config.
          owner_settings = self.class.api_keys_settings
          default_scopes = owner_settings&.[](:default_scopes) || config.default_scopes || []

          # Use provided scopes if given, otherwise use the calculated defaults.
          key_scopes = scopes.nil? ? default_scopes : Array(scopes)

          # Filter scopes based on key type permissions ceiling
          if resolved_key_type.present?
            key_scopes = filter_scopes_by_permissions(key_scopes, resolved_key_type, config)
          end

          # Create the key using the association, letting AR handle owner_id/type.
          api_key = self.api_keys.create!(
            name: name,
            scopes: key_scopes,
            expires_at: expires_at,
            metadata: metadata || {}, # Ensure metadata is at least an empty hash
            key_type: resolved_key_type&.to_s,
            environment: resolved_environment&.to_s
            # prefix, token_digest, digest_algorithm are set by ApiKey callbacks
          )

          # Return the ApiKey instance itself.
          # The plaintext token is available via `api_key.token` immediately after this.
          api_key
        end

        private

        def within_global_quota?
          owner_settings = self.class.api_keys_settings
          limit = owner_settings&.[](:max_keys) || ApiKeys.configuration.default_max_keys_per_owner
          return true unless limit

          api_keys.active.count < limit
        end

        def key_types_feature_enabled?(config)
          config.key_types.present? && config.key_types.any?
        end

        def validate_key_type!(key_type, config)
          return unless key_types_feature_enabled?(config)

          valid_types = config.key_types.keys.map(&:to_sym)
          unless valid_types.include?(key_type.to_sym)
            raise ArgumentError, "Invalid key type '#{key_type}'. Valid types: #{valid_types.join(', ')}"
          end
        end

        def validate_environment!(environment, config)
          return unless config.environments.present? && config.environments.any?

          valid_environments = config.environments.keys.map(&:to_sym)
          unless valid_environments.include?(environment.to_sym)
            raise ArgumentError, "Invalid environment '#{environment}'. Valid environments: #{valid_environments.join(', ')}"
          end
        end

        def resolve_environment(provided_environment, key_type, config)
          # If explicitly provided, use that
          return provided_environment if provided_environment.present?

          # If key_types feature is enabled, use current_environment
          if key_types_feature_enabled?(config) && key_type.present?
            env_lambda = config.current_environment
            return env_lambda.respond_to?(:call) ? env_lambda.call : env_lambda
          end

          nil
        end

        def filter_scopes_by_permissions(scopes, key_type, config)
          return scopes unless key_types_feature_enabled?(config)

          type_config = config.key_types[key_type.to_sym]
          return scopes unless type_config

          permissions = type_config[:permissions]

          # :all means no filtering
          return scopes if permissions == :all

          # Filter to only include scopes that are within the permissions ceiling
          return [] if permissions.nil? || permissions.empty?

          scopes.select { |scope| permissions.include?(scope.to_s) }
        end

        # Check that required columns exist for key_types feature
        # Raises MigrationRequiredError if columns are missing
        def check_required_columns!
          required_columns = %w[key_type environment]
          existing_columns = ApiKeys::ApiKey.column_names

          missing_columns = required_columns - existing_columns

          if missing_columns.any?
            raise ApiKeys::Errors::MigrationRequiredError.new(missing_columns: missing_columns)
          end
        end

        # Example: Check if the owner has reached their API key limit.
        # def reached_api_key_limit?
        #   limit = self.class.api_keys_settings[:max_keys]
        #   # Ensure api_keys association is loaded or query count
        #   limit && api_keys.count >= limit # Or use a counter cache
        # end

        # Example: Get the specific settings for this owner instance's class.
        # def api_keys_config
        #   self.class.api_keys_settings
        # end
      end
    end
  end
end
