# frozen_string_literal: true

require "test_helper"

module ApiKeys
  module Models
    class HasApiKeysTest < ApiKeys::Test
      test "create_api_key locks the owner row before checking quotas and creating" do
        user = User.create!(name: "Concurrent Owner")
        unscoped_relation = mock("unscoped owner relation")
        locked_scope = mock("locked owner scope")
        User.expects(:unscoped).returns(unscoped_relation)
        unscoped_relation.expects(:lock).with(true).returns(locked_scope)
        locked_scope.expects(:find).with(user.id).returns(user)

        key = user.create_api_key!(name: "Serialized Creation")

        assert key.persisted?
      end

      test "direct association creation also locks the owner row" do
        user = User.create!(name: "Direct Creation Owner")
        unscoped_relation = mock("unscoped owner relation")
        locked_scope = mock("locked owner scope")
        User.expects(:unscoped).returns(unscoped_relation)
        unscoped_relation.expects(:lock).with(true).returns(locked_scope)
        locked_scope.expects(:find).with(user.id).returns(user)

        key = user.api_keys.create!(name: "Direct Serialized Creation")

        assert key.persisted?
      end

      test "destroying an owner deletes even non-revocable keys" do
        ApiKeys.configure do |config|
          config.key_types = {
            publishable: {
              prefix: "pk",
              permissions: %w[read],
              public: true,
              revocable: false
            }
          }
          config.environments = { test: { prefix_segment: "test" } }
          config.current_environment = -> { :test }
        end
        user = User.create!(name: "Deletable Owner")
        key = user.create_api_key!(name: "Public Key", key_type: :publishable)

        refute key.revocable?
        assert_difference -> { ApiKeys::ApiKey.count }, -1 do
          user.destroy!
        end
        assert_nil ApiKeys::ApiKey.find_by(id: key.id)
      end

      test "invalid expiration presets do not silently create permanent keys" do
        user = User.create!(name: "Expiration Owner")

        assert_raises(ArgumentError) do
          user.create_api_key!(name: "Must Expire", expires_at_preset: "forever-ish")
        end
        assert_empty user.api_keys
      end

      test "create_api_key! takes expires_in: for a key that lives a while" do
        user = User.create!(name: "Expires In Owner")

        freeze_time do
          assert_equal 7.days.from_now, user.create_api_key!(name: "Week", expires_in: 7.days).expires_at
          assert_equal 1.year.from_now, user.create_api_key!(name: "Year", expires_in: 1.year).expires_at
          assert_equal 12.hours.from_now, user.create_api_key!(name: "CI", expires_in: 12.hours).expires_at
        end
      end

      test "create_api_key! reads every preset the picker offers, and a custom date" do
        user = User.create!(name: "Preset Owner")

        travel_to Time.zone.local(2026, 11, 13, 9, 30) do
          assert_equal 1.day.from_now, user.create_api_key!(name: "Day", expires_at_preset: "1_day").expires_at
          assert_equal 1.year.from_now, user.create_api_key!(name: "Year", expires_at_preset: "1_year").expires_at
          assert_nil user.create_api_key!(name: "Forever", expires_at_preset: "never").expires_at
          assert_equal Time.zone.local(2027, 1, 31, 23, 59, 59),
                       user.create_api_key!(name: "Custom", expires_at_preset: "custom", expires_on: "2027-01-31").expires_at
        end
      end

      test "create_api_key! takes one expiration, not two" do
        user = User.create!(name: "Two Expirations Owner")

        assert_raises(ArgumentError) { user.create_api_key!(name: "Both", expires_in: 7.days, expires_at: 30.days.from_now) }
        assert_raises(ArgumentError) { user.create_api_key!(name: "Both", expires_in: 7.days, expires_at_preset: "30_days") }
        assert_raises(ArgumentError) { user.create_api_key!(name: "Both", expires_on: "2027-01-31", expires_at: 30.days.from_now) }
        assert_empty user.api_keys
      end

      test "create_api_key! takes expires_on: alone as the custom date" do
        user = User.create!(name: "Expires On Owner")

        travel_to Time.zone.local(2026, 11, 13, 9, 30) do
          assert_equal Time.zone.local(2027, 1, 31, 23, 59, 59),
                       user.create_api_key!(name: "Date", expires_on: Date.new(2027, 1, 31)).expires_at
        end
      end

      test "create_api_key! takes a form's empty date field beside a preset" do
        user = User.create!(name: "Form Owner")

        freeze_time do
          # A form submits the Custom date field as "" whatever was chosen.
          assert_equal 30.days.from_now,
                       user.create_api_key!(name: "Month", expires_at_preset: "30_days", expires_on: "").expires_at
          assert_nil user.create_api_key!(name: "Forever", expires_at_preset: "no_expiration", expires_on: "").expires_at
          assert_nil user.create_api_key!(name: "Blank", expires_at_preset: "", expires_on: "").expires_at
        end
      end

      test "create_api_key! uses the date only when Custom is chosen" do
        user = User.create!(name: "Switched Owner")

        freeze_time do
          # Someone picked a date, then switched back to a preset.
          assert_equal 7.days.from_now,
                       user.create_api_key!(name: "Week", expires_at_preset: "7_days", expires_on: "2030-01-01").expires_at
        end
        assert_raises(ApiKeys::Errors::InvalidExpirationError) do
          user.create_api_key!(name: "No Date", expires_at_preset: "custom", expires_on: "")
        end
      end

      test "create_api_key! refuses expires_in: values that are not positive durations" do
        user = User.create!(name: "Bad Expires In Owner")

        [0.days, -1.day, 30, "30 days", Object.new, 3651.days].each do |value|
          assert_raises(ArgumentError, "expected #{value.inspect} to be refused") do
            user.create_api_key!(name: "Bad", expires_in: value)
          end
        end
        assert_empty user.api_keys
      end

      test "per-owner security settings are validated and defensively frozen" do
        owner_class = Class.new(ActiveRecord::Base) do
          self.abstract_class = true
          include ApiKeys::Models::Concerns::HasApiKeys
        end
        scopes = [String.new("read")]

        owner_class.has_api_keys(max_keys: 0, require_name: true, default_scopes: scopes)
        scopes.first.replace("admin")
        scopes << "write"

        assert_equal 0, owner_class.api_keys_settings[:max_keys]
        assert_equal true, owner_class.api_keys_settings[:require_name]
        assert_equal %w[read], owner_class.api_keys_settings[:default_scopes]
        assert owner_class.api_keys_settings.frozen?
        assert owner_class.api_keys_settings[:default_scopes].frozen?
      end

      test "per-owner security settings reject malformed or unknown values" do
        build_owner_class = lambda do
          Class.new(ActiveRecord::Base) do
            self.abstract_class = true
            include ApiKeys::Models::Concerns::HasApiKeys
          end
        end

        assert_raises(ArgumentError) { build_owner_class.call.has_api_keys(max_keys: "10") }
        assert_raises(ArgumentError) { build_owner_class.call.has_api_keys(require_name: "false") }
        assert_raises(ArgumentError) { build_owner_class.call.has_api_keys(default_scopes: ["bad scope"]) }
        assert_raises(ArgumentError) { build_owner_class.call.has_api_keys(unknown_setting: true) }
      end
    end
  end
end
