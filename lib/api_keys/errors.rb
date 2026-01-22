# frozen_string_literal: true

module ApiKeys
  module Errors
    # Base error class for all ApiKeys errors
    class BaseError < StandardError; end

    # Raised when attempting to revoke or destroy a non-revocable key
    class KeyNotRevocableError < BaseError
      def initialize(message = "This API key cannot be revoked or deleted")
        super
      end
    end

    # Raised when API key environment doesn't match current environment (strict isolation)
    class EnvironmentMismatchError < BaseError
      attr_reader :key_environment, :current_environment

      def initialize(key_environment:, current_environment:)
        @key_environment = key_environment
        @current_environment = current_environment
        super("API key environment (#{key_environment}) does not match current environment (#{current_environment})")
      end
    end

    # Raised when an invalid key type is specified
    class InvalidKeyTypeError < BaseError
      attr_reader :key_type, :valid_types

      def initialize(key_type:, valid_types:)
        @key_type = key_type
        @valid_types = valid_types
        super("Invalid key type '#{key_type}'. Valid types: #{valid_types.join(', ')}")
      end
    end

    # Raised when an invalid environment is specified
    class InvalidEnvironmentError < BaseError
      attr_reader :environment, :valid_environments

      def initialize(environment:, valid_environments:)
        @environment = environment
        @valid_environments = valid_environments
        super("Invalid environment '#{environment}'. Valid environments: #{valid_environments.join(', ')}")
      end
    end

    # Raised when key limit per type/environment is exceeded
    class KeyLimitExceededError < BaseError
      attr_reader :key_type, :environment, :limit

      def initialize(key_type:, environment:, limit:)
        @key_type = key_type
        @environment = environment
        @limit = limit
        super("Maximum number of #{key_type} keys (#{limit}) reached for #{environment} environment")
      end
    end

    # Raised when key_types are configured but required database columns are missing
    class MigrationRequiredError < BaseError
      attr_reader :missing_columns

      def initialize(missing_columns:)
        @missing_columns = missing_columns
        super(
          "Key types are configured but required database columns are missing: #{missing_columns.join(', ')}. " \
          "Run: rails generate api_keys:add_key_types && rails db:migrate"
        )
      end
    end
  end
end
