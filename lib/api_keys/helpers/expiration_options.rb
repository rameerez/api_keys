# frozen_string_literal: true

module ApiKeys
  module Helpers
    # Helper for handling API key expiration presets.
    #
    # Provides a consistent set of expiration options for use in forms,
    # and parsing logic to convert preset strings to actual dates.
    #
    # @example In your view (form select)
    #   <%= form.select :expires_at_preset,
    #       ApiKeys::Helpers::ExpirationOptions.for_select %>
    #
    # @example In your controller
    #   expires_at = ApiKeys::Helpers::ExpirationOptions.parse(params[:expires_at_preset])
    #   @api_key = current_org.create_api_key!(expires_at: expires_at, ...)
    #
    class ExpirationOptions
      # Default preset options with human-readable labels
      DEFAULT_PRESETS = [
        { label: "No Expiration", value: "no_expiration", days: nil },
        { label: "7 days", value: "7_days", days: 7 },
        { label: "30 days", value: "30_days", days: 30 },
        { label: "60 days", value: "60_days", days: 60 },
        { label: "90 days", value: "90_days", days: 90 },
        { label: "1 year", value: "365_days", days: 365 }
      ].freeze

      class << self
        # Returns options suitable for a Rails select helper.
        #
        # @param include_no_expiration [Boolean] Whether to include "No Expiration" option (default: true)
        # @param presets [Array<Integer>, nil] Custom list of days to include (e.g., [7, 30, 90])
        #   If nil, uses DEFAULT_PRESETS
        # @return [Array<Array>] Array of [label, value] pairs for select helper
        #
        # @example Default options
        #   ExpirationOptions.for_select
        #   # => [["No Expiration", "no_expiration"], ["7 days", "7_days"], ...]
        #
        # @example Custom presets
        #   ExpirationOptions.for_select(presets: [7, 30, 365])
        #   # => [["No Expiration", "no_expiration"], ["7 days", "7_days"], ["30 days", "30_days"], ["1 year", "365_days"]]
        #
        # @example Without "No Expiration"
        #   ExpirationOptions.for_select(include_no_expiration: false)
        #   # => [["7 days", "7_days"], ["30 days", "30_days"], ...]
        #
        def for_select(include_no_expiration: true, presets: nil)
          options = if presets
                      build_custom_presets(presets, include_no_expiration)
                    else
                      filter_default_presets(include_no_expiration)
                    end

          options.map { |opt| [opt[:label], opt[:value]] }
        end

        # Parse an expiration preset string into an actual datetime.
        #
        # @param preset [String, nil] The preset value (e.g., "30_days", "no_expiration")
        # @return [ActiveSupport::TimeWithZone, nil] The expiration date, or nil for no expiration
        #
        # @example
        #   ExpirationOptions.parse("30_days")  # => 30.days.from_now
        #   ExpirationOptions.parse("no_expiration")  # => nil
        #   ExpirationOptions.parse(nil)  # => nil
        #   ExpirationOptions.parse("invalid")  # => nil
        #
        def parse(preset)
          return nil if preset.blank? || preset == "no_expiration"

          # Try to extract days from the preset string (e.g., "30_days" => 30)
          if preset =~ /\A(\d+)_days?\z/
            days = ::Regexp.last_match(1).to_i
            # Reasonable max: ~10 years to prevent overflow issues
            return days.days.from_now if days.positive? && days <= 3650
          end

          # Check against known presets
          known = DEFAULT_PRESETS.find { |p| p[:value] == preset }
          return known[:days].days.from_now if known && known[:days]

          nil
        end

        # Returns the default preset value (useful for form defaults)
        #
        # @return [String] The default preset value
        def default_value
          "no_expiration"
        end

        private

        def filter_default_presets(include_no_expiration)
          if include_no_expiration
            DEFAULT_PRESETS
          else
            DEFAULT_PRESETS.reject { |p| p[:value] == "no_expiration" }
          end
        end

        def build_custom_presets(days_list, include_no_expiration)
          options = []

          if include_no_expiration
            options << { label: "No Expiration", value: "no_expiration", days: nil }
          end

          days_list.each do |days|
            options << preset_for_days(days)
          end

          options
        end

        def preset_for_days(days)
          label = case days
                  when 1 then "1 day"
                  when 365 then "1 year"
                  when ->(d) { d % 365 == 0 } then "#{days / 365} years"
                  else "#{days} days"
                  end

          { label: label, value: "#{days}_days", days: days }
        end
      end
    end
  end
end
