# frozen_string_literal: true

require "test_helper"

module ApiKeys
  module Helpers
    class ViewHelpersTest < ApiKeys::Test
      include ViewHelpers

      def setup
        super
        @active_key = mock("active_key")
        @active_key.stubs(:revoked?).returns(false)
        @active_key.stubs(:expired?).returns(false)
        @active_key.stubs(:key_type).returns("secret")
        @active_key.stubs(:environment).returns("test")

        @revoked_key = mock("revoked_key")
        @revoked_key.stubs(:revoked?).returns(true)
        @revoked_key.stubs(:expired?).returns(false)
        @revoked_key.stubs(:key_type).returns("secret")
        @revoked_key.stubs(:environment).returns("live")

        @expired_key = mock("expired_key")
        @expired_key.stubs(:revoked?).returns(false)
        @expired_key.stubs(:expired?).returns(true)
        @expired_key.stubs(:key_type).returns("publishable")
        @expired_key.stubs(:environment).returns(nil)

        @publishable_key = mock("publishable_key")
        @publishable_key.stubs(:revoked?).returns(false)
        @publishable_key.stubs(:expired?).returns(false)
        @publishable_key.stubs(:key_type).returns("publishable")
        @publishable_key.stubs(:environment).returns("test")
      end

      # api_key_status tests
      test "api_key_status returns :active for active key" do
        assert_equal :active, api_key_status(@active_key)
      end

      test "api_key_status returns :revoked for revoked key" do
        assert_equal :revoked, api_key_status(@revoked_key)
      end

      test "api_key_status returns :expired for expired key" do
        assert_equal :expired, api_key_status(@expired_key)
      end

      test "api_key_status returns :revoked over :expired when both" do
        key = mock("key")
        key.stubs(:revoked?).returns(true)
        key.stubs(:expired?).returns(true)

        assert_equal :revoked, api_key_status(key)
      end

      # api_key_status_label tests
      test "api_key_status_label returns Active for active key" do
        assert_equal "Active", api_key_status_label(@active_key)
      end

      test "api_key_status_label returns Revoked for revoked key" do
        assert_equal "Revoked", api_key_status_label(@revoked_key)
      end

      test "api_key_status_label returns Expired for expired key" do
        assert_equal "Expired", api_key_status_label(@expired_key)
      end

      # api_key_environment_label tests
      test "api_key_environment_label returns capitalized environment" do
        assert_equal "Test", api_key_environment_label(@active_key)
        assert_equal "Live", api_key_environment_label(@revoked_key)
      end

      test "api_key_environment_label returns Default for blank environment" do
        assert_equal "Default", api_key_environment_label(@expired_key)
      end

      # api_key_type_label tests
      test "api_key_type_label returns Secret for secret key" do
        assert_equal "Secret", api_key_type_label(@active_key)
      end

      test "api_key_type_label returns Publishable for publishable key" do
        assert_equal "Publishable", api_key_type_label(@publishable_key)
      end

      test "api_key_type_label returns Secret for blank key_type" do
        key = mock("key")
        key.stubs(:key_type).returns(nil)

        assert_equal "Secret", api_key_type_label(key)
      end

      test "api_key_type_label returns capitalized custom type" do
        key = mock("key")
        key.stubs(:key_type).returns("custom")

        assert_equal "Custom", api_key_type_label(key)
      end

      # api_key_publishable? tests
      test "api_key_publishable? returns true for publishable key" do
        assert api_key_publishable?(@publishable_key)
      end

      test "api_key_publishable? returns false for secret key" do
        refute api_key_publishable?(@active_key)
      end

      # api_key_secret? tests
      test "api_key_secret? returns true for secret key" do
        assert api_key_secret?(@active_key)
      end

      test "api_key_secret? returns true for nil key_type" do
        key = mock("key")
        key.stubs(:key_type).returns(nil)

        assert api_key_secret?(key)
      end

      test "api_key_secret? returns false for publishable key" do
        refute api_key_secret?(@publishable_key)
      end

      # api_key_environment_from_token tests
      test "api_key_environment_from_token detects test environment" do
        with_environments do
          assert_equal :test, api_key_environment_from_token("sk_test_abc123")
          assert_equal :test, api_key_environment_from_token("pk_test_xyz789")
        end
      end

      test "api_key_environment_from_token detects live environment" do
        with_environments do
          assert_equal :live, api_key_environment_from_token("sk_live_abc123")
          assert_equal :live, api_key_environment_from_token("pk_live_xyz789")
        end
      end

      test "api_key_environment_from_token returns nil for unknown pattern" do
        with_environments do
          assert_nil api_key_environment_from_token("ak_abc123")
          assert_nil api_key_environment_from_token("random_token")
        end
      end

      test "api_key_environment_from_token returns nil for blank token" do
        assert_nil api_key_environment_from_token(nil)
        assert_nil api_key_environment_from_token("")
      end

      test "api_key_environment_from_token returns nil when no environments configured" do
        ApiKeys.configuration.stubs(:environments).returns({})

        assert_nil api_key_environment_from_token("sk_test_abc123")
      end

      # api_key_environment_label_from_token tests
      test "api_key_environment_label_from_token returns formatted label" do
        with_environments do
          assert_equal "Test mode", api_key_environment_label_from_token("sk_test_abc")
          assert_equal "Live mode", api_key_environment_label_from_token("pk_live_xyz")
        end
      end

      test "api_key_environment_label_from_token returns Default for unknown" do
        with_environments do
          assert_equal "Default", api_key_environment_label_from_token("ak_abc123")
        end
      end

      # api_key_status_info tests
      test "api_key_status_info returns hash with status details" do
        info = api_key_status_info(@active_key)

        assert_equal :active, info[:status]
        assert_equal "Active", info[:label]
        assert_equal :green, info[:color]
      end

      test "api_key_status_info returns correct color for revoked" do
        info = api_key_status_info(@revoked_key)

        assert_equal :gray, info[:color]
      end

      test "api_key_status_info returns correct color for expired" do
        info = api_key_status_info(@expired_key)

        assert_equal :red, info[:color]
      end

      # api_key_type_info tests
      test "api_key_type_info returns hash with type details" do
        info = api_key_type_info(@publishable_key)

        assert_equal :publishable, info[:type]
        assert_equal "Publishable", info[:label]
        assert_equal :green, info[:color]
      end

      test "api_key_type_info returns amber for secret" do
        info = api_key_type_info(@active_key)

        assert_equal :secret, info[:type]
        assert_equal :amber, info[:color]
      end

      test "api_key_type_info treats nil key_type as secret" do
        key = mock("key")
        key.stubs(:key_type).returns(nil)

        info = api_key_type_info(key)

        assert_equal :secret, info[:type]
      end

      private

      def with_environments
        original = ApiKeys.configuration.environments
        ApiKeys.configuration.stubs(:environments).returns({
          test: { prefix_segment: "test" },
          live: { prefix_segment: "live" }
        })
        yield
      ensure
        ApiKeys.configuration.unstub(:environments)
      end
    end
  end
end
