# frozen_string_literal: true

require "test_helper"

# Stub helper_method for non-Rails controller context
module Kernel
  def helper_method(*); end
end

module ApiKeys
  class TenantResolutionConcernTest < ApiKeys::Test
    class FakeRequest
      def uuid; SecureRandom.uuid; end
    end

    class FakeController
      include ApiKeys::Authentication
      include ApiKeys::TenantResolution

      def initialize(api_key)
        @api_key = api_key
      end

      # Minimal request needed for Authentication callbacks
      def request
        @request ||= FakeRequest.new
      end

      # Override authenticator usage to set current_api_key directly for isolation
      def set_key(api_key)
        @current_api_key = api_key
      end

      # Satisfy render from Authentication even if not used here
      def render(json:, status:); end
    end

    def setup
      super
      ApiKeys.configure do |c|
        c.enable_async_operations = false
        c.tenant_resolver = ->(api_key) { api_key.owner if api_key.respond_to?(:owner) }
      end
    end

    test "returns owner by default resolver" do
      user = User.create!(name: "Tenant User")
      key = ApiKeys::ApiKey.create!(owner: user, name: "TKey")

      controller = FakeController.new(key)
      controller.set_key(key)

      assert_equal user, controller.send(:current_api_tenant)
      assert_equal user, controller.send(:current_api_key_tenant)
      assert_equal user, controller.send(:current_api_account)
      assert_equal user, controller.send(:current_api_owner)
      assert_equal user, controller.send(:current_api_key_owner)
    end

    test "returns custom tenant via resolver" do
      org = Struct.new(:id).new(42)
      user = User.create!(name: "Org User")
      key = ApiKeys::ApiKey.create!(owner: user, name: "Key")

      ApiKeys.configure { |c| c.tenant_resolver = ->(api_key) { org } }
      controller = FakeController.new(key)
      controller.set_key(key)

      assert_equal org, controller.send(:current_api_tenant)
    end

    test "handles resolver errors and returns nil" do
      user = User.create!(name: "Err User")
      key = ApiKeys::ApiKey.create!(owner: user, name: "Key")

      ApiKeys.configure { |c| c.tenant_resolver = ->(_) { raise "boom" } }
      controller = FakeController.new(key)
      controller.set_key(key)

      assert_nil controller.send(:current_api_tenant)
    end

    test "returns nil when no current_api_key" do
      controller = FakeController.new(nil)
      controller.set_key(nil)
      assert_nil controller.send(:current_api_tenant)
    end
  end
end