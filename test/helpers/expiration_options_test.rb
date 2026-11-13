# frozen_string_literal: true

require "test_helper"

module ApiKeys
  module Helpers
    class ExpirationOptionsTest < ApiKeys::Test
      setup { ApiKeys.reset_configuration! }
      teardown { ApiKeys.reset_configuration! }

      # == for_select ==

      # == choices: the picker, in the configured order ==

      test "choices offer the industry-standard picker by default" do
        assert_equal [["1 day", "1_day"], ["7 days", "7_days"], ["30 days", "30_days"],
                      ["1 year", "1_year"], ["Never", "no_expiration"]],
                     ExpirationOptions.choices
      end

      test "choices offer Custom only to forms that render the date field" do
        assert_equal ["Custom", "custom"], ExpirationOptions.choices(include_custom: true).last
        refute_includes ExpirationOptions.choices.map(&:last), "custom"
      end

      test "choices follow config.expiration_options, in order" do
        ApiKeys.configuration.expiration_options = [:custom, 12.hours, 2.weeks, 3.months, 2.years, :never]

        assert_equal [["Custom", "custom"], ["12 hours", "12_hours"], ["2 weeks", "2_weeks"],
                      ["3 months", "3_months"], ["2 years", "2_years"], ["Never", "no_expiration"]],
                     ExpirationOptions.choices(include_custom: true)
      end

      test "choices without Never" do
        options = ExpirationOptions.choices(include_no_expiration: false)

        refute_includes options.map(&:last), "no_expiration"
        assert_equal ["1 day", "1_day"], options.first
      end

      # == for_select: exactly what 0.9 returned, so upgrading forms keep their selection ==

      test "0.9 contract: for_select returns default options" do
        options = ExpirationOptions.for_select

        assert_equal 6, options.length
        assert_equal ["No Expiration", "no_expiration"], options.first
        assert_equal ["7 days", "7_days"], options[1]
        assert_equal ["1 year", "365_days"], options.last
      end

      test "0.9 contract: for_select without no_expiration option" do
        options = ExpirationOptions.for_select(include_no_expiration: false)

        assert_equal 5, options.length
        refute(options.any? { |label, _| label == "No Expiration" })
        assert_equal ["7 days", "7_days"], options.first
      end

      test "0.9 contract: for_select with custom presets" do
        options = ExpirationOptions.for_select(presets: [7, 30, 365])

        assert_equal 4, options.length # includes "No Expiration"
        assert_equal ["No Expiration", "no_expiration"], options.first
        assert_equal ["7 days", "7_days"], options[1]
        assert_equal ["30 days", "30_days"], options[2]
        assert_equal ["1 year", "365_days"], options[3]
      end

      test "0.9 contract: for_select with custom presets without no_expiration" do
        options = ExpirationOptions.for_select(presets: [7, 30], include_no_expiration: false)

        assert_equal 2, options.length
        assert_equal ["7 days", "7_days"], options.first
        assert_equal ["30 days", "30_days"], options.last
      end

      test "0.9 contract: for_select generates correct label for 1 day" do
        options = ExpirationOptions.for_select(presets: [1])

        assert_equal ["1 day", "1_days"], options[1]
      end

      test "0.9 contract: for_select generates correct label for multiple years" do
        options = ExpirationOptions.for_select(presets: [730])

        assert_equal ["2 years", "730_days"], options[1]
      end

      test "for_select is the same whatever config.expiration_options says" do
        ApiKeys.configuration.expiration_options = [1.day, :custom]

        assert_equal [["No Expiration", "no_expiration"], ["7 days", "7_days"], ["30 days", "30_days"],
                      ["60 days", "60_days"], ["90 days", "90_days"], ["1 year", "365_days"]],
                     ExpirationOptions.for_select
      end

      test "for_select can add Custom and previews, for forms that want them" do
        travel_to Time.zone.local(2026, 11, 13, 9, 30) do
          options = ExpirationOptions.for_select(include_custom: true, preview: true)

          assert_equal ["7 days", "7_days", { "data-api-keys-expires-on" => "November 20, 2026" }], options[1]
          assert_equal ["Custom", "custom"], options.last
        end
      end

      test "every value for_select offers parses" do
        ExpirationOptions.for_select(presets: [1, 7, 730, 3650.days, 1.year]).each do |_label, value|
          ExpirationOptions.parse(value) # must not raise
        end
      end

      # == config.expire_after ==

      test "with config.expire_after, the never option names that lifetime instead of promising Never" do
        ApiKeys.configuration.expire_after = 90.days

        travel_to Time.zone.local(2026, 11, 13, 9, 30) do
          assert_equal ["90 days (default)", "no_expiration"], ExpirationOptions.choices.last
          assert_equal ["No Expiration", "no_expiration"], ExpirationOptions.for_select.first, "unchanged from 0.9"
          assert_equal ["90 days (default)", "no_expiration", { "data-api-keys-expires-on" => "February 11, 2027" }],
                       ExpirationOptions.choices(preview: true).last
        end
        assert ExpirationOptions.offered?("no_expiration"), "forms that preselect no_expiration keep a matching option"
      end

      test "for_select still takes durations as presets" do
        assert_equal [["7 days", "7_days"], ["1 year", "1_year"]],
                     ExpirationOptions.for_select(presets: [7.days, 1.year], include_no_expiration: false)
      end

      test "custom presets must be bounded positive integers or durations" do
        assert_raises(ArgumentError) { ExpirationOptions.for_select(presets: "30") }
        assert_raises(ArgumentError) { ExpirationOptions.for_select(presets: [0, 30]) }
        assert_raises(ArgumentError) { ExpirationOptions.for_select(presets: [3651]) }
        assert_raises(ArgumentError) { ExpirationOptions.for_select(presets: [11.years]) }
        assert_raises(ArgumentError) { ExpirationOptions.for_select(presets: [1.day + 2.hours]) }
      end

      # == parse ==

      test "parse returns nil for Never, under either name" do
        assert_nil ExpirationOptions.parse("no_expiration")
        assert_nil ExpirationOptions.parse("never")
      end

      test "parse returns nil for blank value" do
        assert_nil ExpirationOptions.parse(nil)
        assert_nil ExpirationOptions.parse("")
      end

      test "parse reads every unit, singular or plural" do
        freeze_time do
          assert_equal 12.hours.from_now, ExpirationOptions.parse("12_hours")
          assert_equal 1.day.from_now, ExpirationOptions.parse("1_day")
          assert_equal 1.day.from_now, ExpirationOptions.parse("1_days")
          assert_equal 30.days.from_now, ExpirationOptions.parse("30_days")
          assert_equal 2.weeks.from_now, ExpirationOptions.parse("2_weeks")
          assert_equal 3.months.from_now, ExpirationOptions.parse("3_months")
          assert_equal 1.year.from_now, ExpirationOptions.parse("1_year")
          assert_equal 365.days.from_now, ExpirationOptions.parse("365_days")
        end
      end

      test "every value choices offers parses" do
        ApiKeys.configuration.expiration_options = [1.hour, 1.day, 1.week, 1.month, 1.year, 9.years, :never, :custom]

        ExpirationOptions.choices.each do |_label, value|
          ExpirationOptions.parse(value) # must not raise
        end
      end

      test "parse rejects invalid presets instead of silently removing expiration" do
        %w[invalid abc_days 0_days 1_fortnight custom_days].each do |preset|
          assert_raises(ArgumentError) { ExpirationOptions.parse(preset) }
        end
      end

      test "parse rejects anything past ten years" do
        assert_raises(ArgumentError) { ExpirationOptions.parse("99999999999_days") }
        assert_raises(ArgumentError) { ExpirationOptions.parse("3651_days") }
        assert_raises(ArgumentError) { ExpirationOptions.parse("11_years") }
        assert_raises(ArgumentError) { ExpirationOptions.parse("10_years") } # 10 calendar years > 3650 days
        assert_raises(ArgumentError) { ExpirationOptions.parse("87601_hours") }
        assert_raises(ArgumentError) { ExpirationOptions.parse("9" * 100_000 + "_days") }
        assert_raises(ArgumentError) { ExpirationOptions.parse({ days: 30 }) }
      end

      test "parse accepts exactly the maximum" do
        freeze_time do
          assert_equal 3650.days.from_now, ExpirationOptions.parse("3650_days")
          assert_equal 9.years.from_now, ExpirationOptions.parse("9_years")
        end
      end

      test "parse rejects negative and zero amounts" do
        %w[0_days -1_days -365_days 0_hours 0_years].each do |preset|
          assert_raises(ArgumentError) { ExpirationOptions.parse(preset) }
        end
      end

      # == Custom date ==

      test "a custom date expires at the end of that day, in the app's time zone" do
        travel_to Time.zone.local(2026, 11, 13, 9, 30) do
          expires_at = ExpirationOptions.parse("custom", on: "2027-01-31")

          assert_equal Time.zone.local(2027, 1, 31, 23, 59, 59), expires_at
          assert_equal Time.zone.local(2027, 1, 31, 23, 59, 59), ExpirationOptions.parse("custom", on: Date.new(2027, 1, 31))
        end
      end

      test "a custom date of today expires tonight" do
        travel_to Time.zone.local(2026, 11, 13, 9, 30) do
          assert_equal Time.zone.local(2026, 11, 13, 23, 59, 59), ExpirationOptions.parse("custom", on: "2026-11-13")
        end
      end

      test "a past custom date is returned, so the model refuses it with a readable error" do
        travel_to Time.zone.local(2026, 11, 13, 9, 30) do
          assert_equal Time.zone.local(2026, 11, 12, 23, 59, 59), ExpirationOptions.parse("custom", on: "2026-11-12")
        end
      end

      test "Custom without a readable date is refused with a message a person can act on" do
        [nil, "", "   ", "tomorrow", "2027-02-30", "31/01/2027", "2027-1-1x", 20_270_131, "9" * 10_000].each do |date|
          error = assert_raises(ApiKeys::Errors::InvalidExpirationError) { ExpirationOptions.parse("custom", on: date) }
          assert_equal "Pick the date the key expires.", error.message
        end
      end

      test "a custom date past ten years is refused" do
        travel_to Time.zone.local(2026, 11, 13, 9, 30) do
          assert ExpirationOptions.parse("custom", on: "2036-11-10") # Date.current + 3650 days
          error = assert_raises(ApiKeys::Errors::InvalidExpirationError) { ExpirationOptions.parse("custom", on: "2036-11-11") }
          assert_equal "A key can expire at most 10 years from now.", error.message
        end
      end

      test "a custom expiration error is still an ArgumentError, as before" do
        assert_operator ApiKeys::Errors::InvalidExpirationError, :<, ArgumentError
      end

      # == offered? and the dates a form can preview ==

      test "offered? answers for exactly the values the form shows" do
        assert ExpirationOptions.offered?("7_days")
        assert ExpirationOptions.offered?("never") # alias of no_expiration
        refute ExpirationOptions.offered?("custom")
        assert ExpirationOptions.offered?("custom", include_custom: true)
        refute ExpirationOptions.offered?("60_days")
        refute ExpirationOptions.offered?(nil)
        refute ExpirationOptions.offered?(["7_days"])
      end

      test "a preview never dates Never" do
        assert_equal ["Never", "no_expiration"], ExpirationOptions.choices(preview: true).last
      end

      test "custom_offered? follows the configuration" do
        assert ExpirationOptions.custom_offered?
        ApiKeys.configuration.expiration_options = [7.days, :never]
        refute ExpirationOptions.custom_offered?
      end

      test "default_value is still Never, for forms written against earlier versions" do
        assert_equal "no_expiration", ExpirationOptions.default_value
      end
    end
  end
end
