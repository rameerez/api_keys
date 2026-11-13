# frozen_string_literal: true

module ApiKeys
  module Helpers
    # The expiration picker: what a new key's form offers, and how each choice
    # becomes an `expires_at`.
    #
    # The choices come from `config.expiration_options`, which defaults to the
    # picker OpenAI and most API dashboards use:
    #
    #   1 day · 7 days · 30 days · 1 year · Never · Custom
    #
    # A choice travels through the form as a preset string: "1_day",
    # "30_days", "1_year", "12_hours", "no_expiration" (or "never"), and
    # "custom", which takes the date the key expires.
    #
    # @example In your view
    #   <%= form.select :expires_at_preset, ApiKeys::ExpirationOptions.for_select %>
    #
    # @example In your controller
    #   expires_at = ApiKeys::ExpirationOptions.parse(params[:expires_at_preset])
    #   ApiKeys::ExpirationOptions.parse("custom", on: "2027-01-31") # => end of that day
    #
    class ExpirationOptions
      # The longest a key can be set to live, in days (about ten years).
      MAX_DAYS = 3650
      # The symbols config.expiration_options takes beside durations.
      CHOICES = %i[never custom].freeze
      NEVER = "no_expiration"
      CUSTOM = "custom"
      # The units a preset can name, smallest first.
      UNITS = %w[hour day week month year].freeze
      PRESET_FORMAT = /\A(\d{1,6})_(#{UNITS.join('|')})s?\z/
      DATE_FORMAT = /\A\d{4}-\d{2}-\d{2}\z/
      DATE_LABEL = "%B %-d, %Y"

      class << self
        # The picker's options, in the order `config.expiration_options`
        # lists them, as [label, value] pairs for a Rails select helper. Ask
        # for a choice with a prompt (see `form.api_key_expiration_select`),
        # since a browser preselects the first option.
        #
        # @param include_no_expiration [Boolean] Offer the never option
        #   (default: true). While `config.expire_after` is set it names that
        #   lifetime ("90 days (default)") instead of promising "Never": its
        #   value, "no_expiration", has always meant "no expiration of my own".
        # @param include_custom [Boolean] Offer "Custom" (default: false). Only
        #   a form that also renders the date field (`expires_on`) can use it.
        # @param preview [Boolean] Add each choice's expiration date as a
        #   `data-api-keys-expires-on` attribute, so the form can show it.
        # @return [Array<Array>]
        #
        # @example
        #   ExpirationOptions.choices
        #   # => [["1 day", "1_day"], ["7 days", "7_days"], ["30 days", "30_days"],
        #   #     ["1 year", "1_year"], ["Never", "no_expiration"]]
        #
        def choices(include_no_expiration: true, include_custom: false, preview: false)
          build_options(ApiKeys.configuration.expiration_options, include_no_expiration, include_custom, preview)
        end

        # The same options with the never option first, as before 0.10: a form
        # built on it with nothing selected still defaults to no expiration of
        # its own, never to "1 day".
        #
        # @param presets [Array<Integer, ActiveSupport::Duration>, nil] Offer
        #   these instead of `config.expiration_options`: whole days, or durations.
        # @see .choices for the other parameters
        # @return [Array<Array>]
        #
        # @example
        #   ExpirationOptions.for_select
        #   # => [["Never", "no_expiration"], ["1 day", "1_day"], ["7 days", "7_days"],
        #   #     ["30 days", "30_days"], ["1 year", "1_year"]]
        #
        def for_select(include_no_expiration: true, include_custom: false, presets: nil, preview: false)
          configured = presets ? choices_from_presets(presets) : ApiKeys.configuration.expiration_options
          options = build_options(configured, include_no_expiration, include_custom, preview)
          options.partition { |option| option[1] == NEVER }.flatten(1)
        end

        # Turns a preset into the moment the key expires.
        #
        # @param preset [String, nil] "30_days", "1_year", "no_expiration", "custom"...
        # @param on [String, Date, nil] With "custom": the day the key expires
        #   ("2027-01-31"). The key expires at 23:59:59 that day, in the
        #   app's time zone.
        # @return [ActiveSupport::TimeWithZone, nil] nil means the key never expires.
        # @raise [ArgumentError] for anything else, so a typo never makes a
        #   key permanent. A missing or out-of-range custom date raises
        #   ApiKeys::Errors::InvalidExpirationError (an ArgumentError) with a
        #   message a person can act on.
        #
        # @example
        #   ExpirationOptions.parse("30_days")      # => 30.days.from_now
        #   ExpirationOptions.parse("never")        # => nil
        #   ExpirationOptions.parse("custom", on: "2027-01-31") # => 2027-01-31 23:59:59
        #
        def parse(preset, on: nil)
          return nil if preset.nil? || preset == ""
          unless preset.is_a?(String) && preset.valid_encoding? && preset.bytesize <= 32
            raise ArgumentError, "Invalid API key expiration preset"
          end
          return nil if preset == NEVER || preset == "never"
          return custom_date(on) if preset == CUSTOM

          duration = duration_for(preset)
          raise ArgumentError, "Invalid API key expiration preset" unless duration

          duration.from_now
        end

        # Whether the form offers this preset ("never" counts as "no_expiration").
        #
        # @param preset [String]
        # @param include_custom [Boolean] Whether the form offers "Custom".
        # @return [Boolean]
        def offered?(preset, include_custom: false)
          return false unless preset.is_a?(String)

          preset = NEVER if preset == "never"
          choices(include_custom: include_custom).any? { |_label, value| value == preset }
        end

        # Whether `config.expiration_options` offers a custom date.
        def custom_offered?
          ApiKeys.configuration.expiration_options.include?(:custom)
        end

        # Whether `config.expiration_options` offers the never option (named
        # after `config.expire_after` while that is set).
        def never_offered?
          ApiKeys.configuration.expiration_options.include?(:never)
        end

        # The earliest and latest day a custom date can be, as the date
        # field's min and max.
        #
        # @return [Hash] { min: "2026-11-14", max: "2036-11-10" }
        def custom_date_range
          { min: (Date.current + 1).iso8601, max: (Date.current + MAX_DAYS).iso8601 }
        end

        # The preset string for a duration, or nil when the picker cannot
        # offer it (not a whole number of one unit, not positive, or longer
        # than ten years).
        #
        # @param duration [ActiveSupport::Duration]
        # @return [String, nil] "1_day", "2_weeks", "1_year"...
        def preset_for(duration)
          return nil unless duration.is_a?(ActiveSupport::Duration) && duration.parts.size == 1

          unit, amount = duration.parts.first
          unit = unit.to_s.delete_suffix("s")
          return nil unless UNITS.include?(unit) && amount.is_a?(Integer)

          preset = "#{amount}_#{unit.pluralize(amount)}"
          preset if duration_for(preset)
        end

        # The default selection of forms written before 0.10.
        #
        # @return [String] "no_expiration"
        def default_value
          NEVER
        end

        private

        def build_options(configured, include_no_expiration, include_custom, preview)
          configured = configured.reject { |choice| choice == :never } unless include_no_expiration
          configured = configured.reject { |choice| choice == :custom } unless include_custom

          configured.map do |choice|
            option = [label_for(choice), value_for(choice)]
            expires_at = preview_time(choice)
            option << { "data-api-keys-expires-on" => expires_at.strftime(DATE_LABEL) } if preview && expires_at
            option
          end
        end

        # When a choice expires a key made now, or nil (Never, Custom).
        def preview_time(choice)
          return choice.from_now if choice.is_a?(ActiveSupport::Duration)

          ApiKeys.configuration.expire_after&.from_now if choice == :never
        end

        def duration_for(preset)
          match = PRESET_FORMAT.match(preset)
          return nil unless match

          amount = match[1].to_i
          duration = amount.public_send(match[2].pluralize)
          duration if amount.positive? && duration.to_i <= MAX_DAYS.days.to_i
        end

        def custom_date(on)
          date = case on
                 when Date then on
                 when String then parse_date(on.strip)
                 end
          raise ApiKeys::Errors::InvalidExpirationError, "Pick the date the key expires." unless date
          if date > Date.current + MAX_DAYS
            raise ApiKeys::Errors::InvalidExpirationError, "A key can expire at most 10 years from now."
          end

          # 23:59:59 sharp: a fractional end_of_day would round up to the next
          # midnight in a datetime column without sub-second precision (MySQL).
          (Time.zone || Time.find_zone!("UTC")).local(date.year, date.month, date.day, 23, 59, 59)
        end

        def parse_date(text)
          Date.iso8601(text) if text.valid_encoding? && text.match?(DATE_FORMAT)
        rescue Date::Error
          nil
        end

        def label_for(choice)
          case choice
          when :never then never_label
          when :custom then "Custom"
          else
            unit, amount = choice.parts.first
            unit = unit.to_s.delete_suffix("s")
            # 365.days reads "1 year", as it did before 0.10.
            unit, amount = "year", amount / 365 if unit == "day" && (amount % 365).zero?
            "#{amount} #{unit.pluralize(amount)}"
          end
        end

        # config.expire_after gives a key without an expiration of its own
        # that lifetime, so the never option names it.
        def never_label
          expire_after = ApiKeys.configuration.expire_after
          return "Never" if expire_after.nil?

          lifetime = expire_after.is_a?(ActiveSupport::Duration) ? expire_after : expire_after.seconds
          "#{lifetime.inspect} (default)"
        end

        def value_for(choice)
          case choice
          when :never then NEVER
          when :custom then CUSTOM
          else preset_for(choice)
          end
        end

        # Whole days (as before 0.10) or durations, with "Never" first.
        def choices_from_presets(presets)
          # A Duration answers is_a?(Integer) with true, so ask about it first.
          durations = presets.map { |days| days.is_a?(ActiveSupport::Duration) || !days.is_a?(Integer) ? days : days.days } if presets.is_a?(Array)
          unless durations&.all? { |duration| preset_for(duration) }
            raise ArgumentError, "Expiration presets must be whole days or durations, from 1 day up to ten years"
          end

          [:never, *durations]
        end
      end
    end
  end
end
