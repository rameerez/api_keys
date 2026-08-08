# frozen_string_literal: true

require "test_helper"

module ApiKeys
  module Helpers
    class ExpirationOptionsTest < ApiKeys::Test
      test "for_select returns default options" do
        options = ExpirationOptions.for_select

        assert_equal 6, options.length
        assert_equal ["No Expiration", "no_expiration"], options.first
        assert_equal ["7 days", "7_days"], options[1]
        assert_equal ["1 year", "365_days"], options.last
      end

      test "for_select without no_expiration option" do
        options = ExpirationOptions.for_select(include_no_expiration: false)

        assert_equal 5, options.length
        refute(options.any? { |label, _| label == "No Expiration" })
        assert_equal ["7 days", "7_days"], options.first
      end

      test "for_select with custom presets" do
        options = ExpirationOptions.for_select(presets: [7, 30, 365])

        assert_equal 4, options.length # includes "No Expiration"
        assert_equal ["No Expiration", "no_expiration"], options.first
        assert_equal ["7 days", "7_days"], options[1]
        assert_equal ["30 days", "30_days"], options[2]
        assert_equal ["1 year", "365_days"], options[3]
      end

      test "for_select with custom presets without no_expiration" do
        options = ExpirationOptions.for_select(presets: [7, 30], include_no_expiration: false)

        assert_equal 2, options.length
        assert_equal ["7 days", "7_days"], options.first
        assert_equal ["30 days", "30_days"], options.last
      end

      test "for_select generates correct label for 1 day" do
        options = ExpirationOptions.for_select(presets: [1])

        assert_equal ["1 day", "1_days"], options[1]
      end

      test "for_select generates correct label for multiple years" do
        options = ExpirationOptions.for_select(presets: [730])

        assert_equal ["2 years", "730_days"], options[1]
      end

      test "parse returns nil for no_expiration" do
        result = ExpirationOptions.parse("no_expiration")

        assert_nil result
      end

      test "parse returns nil for blank value" do
        assert_nil ExpirationOptions.parse(nil)
        assert_nil ExpirationOptions.parse("")
      end

      test "parse returns correct date for days preset" do
        freeze_time do
          result = ExpirationOptions.parse("30_days")

          assert_in_delta 30.days.from_now.to_i, result.to_i, 1
        end
      end

      test "parse handles singular day preset" do
        freeze_time do
          result = ExpirationOptions.parse("1_day")

          assert_in_delta 1.day.from_now.to_i, result.to_i, 1
        end
      end

      test "parse rejects invalid presets instead of silently removing expiration" do
        %w[invalid abc_days 0_days].each do |preset|
          assert_raises(ArgumentError) { ExpirationOptions.parse(preset) }
        end
      end

      test "parse rejects excessively large days values" do
        assert_raises(ArgumentError) { ExpirationOptions.parse("99999999999_days") }
        assert_raises(ArgumentError) { ExpirationOptions.parse("3651_days") }
        assert_raises(ArgumentError) { ExpirationOptions.parse("9" * 100_000 + "_days") }
        assert_raises(ArgumentError) { ExpirationOptions.parse({ days: 30 }) }
      end

      test "parse accepts maximum allowed days" do
        freeze_time do
          result = ExpirationOptions.parse("3650_days")

          assert_in_delta 3650.days.from_now.to_i, result.to_i, 1
        end
      end

      test "parse boundary conditions for max days" do
        freeze_time do
          # 3650 days (exactly 10 years) should work
          assert_not_nil ExpirationOptions.parse("3650_days")

          # 3651 days (just over 10 years) must fail closed
          assert_raises(ArgumentError) { ExpirationOptions.parse("3651_days") }

          # Large but valid values
          result = ExpirationOptions.parse("1000_days")
          assert_in_delta 1000.days.from_now.to_i, result.to_i, 1
        end
      end

      test "parse rejects negative and zero days" do
        %w[0_days -1_days -365_days].each do |preset|
          assert_raises(ArgumentError) { ExpirationOptions.parse(preset) }
        end
      end

      test "custom presets must be bounded positive integers" do
        assert_raises(ArgumentError) { ExpirationOptions.for_select(presets: "30") }
        assert_raises(ArgumentError) { ExpirationOptions.for_select(presets: [0, 30]) }
        assert_raises(ArgumentError) { ExpirationOptions.for_select(presets: [3651]) }
      end

      test "parse works with known presets" do
        freeze_time do
          result = ExpirationOptions.parse("365_days")

          assert_in_delta 365.days.from_now.to_i, result.to_i, 1
        end
      end

      test "default_value returns no_expiration" do
        assert_equal "no_expiration", ExpirationOptions.default_value
      end
    end
  end
end
