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
              default_scopes: ApiKeys.configuration&.default_scopes || [],
              token_prefix: ApiKeys.configuration&.token_prefix # Add token_prefix default
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

          def token_prefix(value)
            # Store the string or proc provided
            @settings[:token_prefix] = value
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

        # Creates a new API key for this owner instance and returns the plaintext token.
        # Raises ActiveRecord::RecordInvalid if creation fails.
        #
        # @param name [String] The name for the new API key (required).
        # @param scopes [Array<String>, nil] Scopes for the key. Defaults to owner/global settings.
        # @param expires_at [Time, nil] Optional expiration timestamp.
        # @param metadata [Hash, nil] Optional metadata hash.
        # @return [String] The plaintext API key token (e.g., "ak_test_...").
        def create_api_key!(name: nil, scopes: nil, expires_at: nil, metadata: nil)
          # Fetch default scopes from this owner class's settings, falling back to global config.
          owner_settings = self.class.api_keys_settings
          default_scopes = owner_settings&.[](:default_scopes) || ApiKeys.configuration.default_scopes || []

          # Use provided scopes if given, otherwise use the calculated defaults.
          key_scopes = scopes.nil? ? default_scopes : Array(scopes)

          # Create the key using the association, letting AR handle owner_id/type.
          api_key = self.api_keys.create!(
            name: name,
            scopes: key_scopes,
            expires_at: expires_at,
            metadata: metadata || {} # Ensure metadata is at least an empty hash
            # prefix, token_digest, digest_algorithm are set by ApiKey callbacks
          )

          # Return the plaintext token which is available via attr_reader after creation.
          api_key.token
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
