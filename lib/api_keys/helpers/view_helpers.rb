# frozen_string_literal: true

module ApiKeys
  module Helpers
    # View helpers for displaying API key information.
    #
    # These helpers provide formatted data without HTML opinions,
    # allowing integrators to build their own UI while using
    # consistent data formatting.
    #
    # @example Include in your ApplicationHelper
    #   module ApplicationHelper
    #     include ApiKeys::Helpers::ViewHelpers
    #   end
    #
    # @example Or include in a specific controller
    #   class Settings::ApiKeysController < ApplicationController
    #     helper ApiKeys::Helpers::ViewHelpers
    #   end
    #
    module ViewHelpers
      # Returns the status of an API key as a symbol.
      #
      # @param api_key [ApiKeys::ApiKey] The API key
      # @return [Symbol] :active, :expired, or :revoked
      #
      # @example
      #   api_key_status(@key) # => :active
      #
      def api_key_status(api_key)
        return :revoked if api_key.revoked?
        return :expired if api_key.expired?

        :active
      end

      # Returns a human-readable status label for an API key.
      #
      # @param api_key [ApiKeys::ApiKey] The API key
      # @return [String] "Active", "Expired", or "Revoked"
      #
      # @example
      #   api_key_status_label(@key) # => "Active"
      #
      def api_key_status_label(api_key)
        case api_key_status(api_key)
        when :active then "Active"
        when :expired then "Expired"
        when :revoked then "Revoked"
        end
      end

      # Returns the environment label for an API key.
      #
      # @param api_key [ApiKeys::ApiKey] The API key
      # @return [String] "Test", "Live", or "Default" (if no environment set)
      #
      # @example
      #   api_key_environment_label(@key) # => "Live"
      #
      def api_key_environment_label(api_key)
        return "Default" if api_key.environment.blank?

        api_key.environment.to_s.capitalize
      end

      # Returns the key type label for an API key.
      #
      # @param api_key [ApiKeys::ApiKey] The API key
      # @return [String] "Publishable", "Secret", or the key_type capitalized
      #
      # @example
      #   api_key_type_label(@key) # => "Secret"
      #
      def api_key_type_label(api_key)
        return "Secret" if api_key.key_type.blank?

        case api_key.key_type.to_s
        when "publishable" then "Publishable"
        when "secret" then "Secret"
        else api_key.key_type.to_s.capitalize
        end
      end

      # Returns whether the key is a publishable (public) key type.
      # Useful for conditional rendering (e.g., showing/hiding copy button).
      #
      # @param api_key [ApiKeys::ApiKey] The API key
      # @return [Boolean] true if the key is publishable
      #
      # @example
      #   <% if api_key_publishable?(@key) %>
      #     <%= button_tag "Copy", data: { token: @key.viewable_token } %>
      #   <% end %>
      #
      def api_key_publishable?(api_key)
        api_key.key_type.to_s == "publishable"
      end

      # Returns whether the key is a secret key type.
      #
      # @param api_key [ApiKeys::ApiKey] The API key
      # @return [Boolean] true if the key is secret (or legacy with no type)
      #
      def api_key_secret?(api_key)
        api_key.key_type.blank? || api_key.key_type.to_s == "secret"
      end

      # Detects the environment from a token string by parsing its prefix.
      # Useful for displaying environment info when you only have the token.
      #
      # @param token [String] The full token string (e.g., "sk_test_abc123...")
      # @return [Symbol, nil] The detected environment (:test, :live, etc.) or nil
      #
      # @example
      #   api_key_environment_from_token("sk_test_abc123") # => :test
      #   api_key_environment_from_token("pk_live_xyz789") # => :live
      #   api_key_environment_from_token("ak_abc123")      # => nil
      #
      def api_key_environment_from_token(token)
        return nil if token.blank?
        return nil if token.length > 500 # Reasonable max length for tokens

        config = ApiKeys.configuration
        return nil unless config.environments.present?

        # Check each configured environment's prefix segment
        config.environments.each do |env_name, env_config|
          segment = env_config[:prefix_segment]
          next if segment.blank?

          # Match pattern like _test_ or _live_ in the token
          if token.include?("_#{segment}_")
            return env_name
          end
        end

        nil
      end

      # Returns a human-readable environment label from a token string.
      # Convenience wrapper around api_key_environment_from_token.
      #
      # @param token [String] The full token string
      # @return [String] "Test mode", "Live mode", or "Default" if unknown
      #
      # @example
      #   api_key_environment_label_from_token("sk_test_abc") # => "Test mode"
      #   api_key_environment_label_from_token("sk_live_xyz") # => "Live mode"
      #
      def api_key_environment_label_from_token(token)
        env = api_key_environment_from_token(token)
        return "Default" if env.nil?

        "#{env.to_s.capitalize} mode"
      end

      # Returns a hash of status information for an API key.
      # Useful for building custom status badges.
      #
      # @param api_key [ApiKeys::ApiKey] The API key
      # @return [Hash] Hash with :status, :label, and :color keys
      #
      # @example
      #   info = api_key_status_info(@key)
      #   # => { status: :active, label: "Active", color: :green }
      #
      def api_key_status_info(api_key)
        status = api_key_status(api_key)
        {
          status: status,
          label: api_key_status_label(api_key),
          color: status_color(status)
        }
      end

      # Returns a hash of type information for an API key.
      # Useful for building custom type badges.
      #
      # @param api_key [ApiKeys::ApiKey] The API key
      # @return [Hash] Hash with :type, :label, and :color keys
      #
      # @example
      #   info = api_key_type_info(@key)
      #   # => { type: :publishable, label: "Publishable", color: :green }
      #
      def api_key_type_info(api_key)
        type = case api_key.key_type.to_s
               when "", "secret" then :secret
               when "publishable" then :publishable
               else api_key.key_type.to_s
               end
        {
          type: type,
          label: api_key_type_label(api_key),
          color: type_color(type)
        }
      end

      private

      def status_color(status)
        case status
        when :active then :green
        when :expired then :red
        when :revoked then :gray
        else :gray
        end
      end

      def type_color(type)
        case type
        when :publishable then :green
        when :secret then :amber
        else :gray
        end
      end
    end
  end
end
