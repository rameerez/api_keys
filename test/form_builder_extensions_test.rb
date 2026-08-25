# frozen_string_literal: true

require "test_helper"

module ApiKeys
  class FormBuilderExtensionsTest < ApiKeys::Test
    FakeObject = Struct.new(:persisted?, :scopes, :key_type, :environment, keyword_init: true) do
      def masked_token = "pk_test_••••abcd"
      def viewable_token = "pk_test_full"
      def public_key_type? = true
    end

    class FakeTemplate
      def options_for_select(options, selected)
        { options: options, selected: selected }
      end

      def capture
        yield
      end
    end

    class FakeBuilder
      include ApiKeys::FormBuilderExtensions

      attr_reader :object, :object_name, :template

      def initialize(object: nil)
        @object = object
        @object_name = "api_key"
        @template = FakeTemplate.new
      end

      def select(*arguments)
        arguments
      end
    end

    test "expiration select honors a selected preset and preserves options" do
      builder = FakeBuilder.new

      arguments = builder.api_key_expiration_select({ selected: "30_days", include_blank: true }, class: "expiry")

      assert_equal :expires_at_preset, arguments[0]
      assert_equal "30_days", arguments[1][:selected]
      assert_equal({ include_blank: true }, arguments[2])
      assert_equal({ class: "expiry" }, arguments[3])
      assert_equal ApiKeys::ExpirationOptions.default_value,
                   builder.api_key_expiration_select[1][:selected]
    end

    test "scope data supports every checked policy" do
      new_builder = FakeBuilder.new(object: FakeObject.new(persisted?: false, scopes: ["read"]))
      persisted_builder = FakeBuilder.new(object: FakeObject.new(persisted?: true, scopes: ["write"]))
      scopes = %w[read write]

      assert_equal [true, true], new_builder.api_key_scopes_checkboxes(scopes, checked: :all).pluck(:checked)
      assert_equal [false, false], new_builder.api_key_scopes_checkboxes(scopes, checked: :none).pluck(:checked)
      assert_equal [false, true], new_builder.api_key_scopes_checkboxes(scopes, checked: [:write]).pluck(:checked)
      assert_equal [true, true], new_builder.api_key_scopes_checkboxes(scopes).pluck(:checked)
      assert_equal [false, true], persisted_builder.api_key_scopes_checkboxes(scopes).pluck(:checked)
      assert_equal [true, true], new_builder.api_key_scopes_checkboxes(scopes, checked: Object.new).pluck(:checked)
      assert_equal "api_key[scopes][]", new_builder.api_key_scopes_checkboxes(scopes).first[:field_name]
    end

    test "scope rendering captures each custom row into a safe buffer" do
      builder = FakeBuilder.new

      html = builder.api_key_scopes_checkboxes(%w[read write], checked: [:read]) do |scope, checked|
        ERB::Util.html_escape("<#{scope}:#{checked}>")
      end

      assert_instance_of ActiveSupport::SafeBuffer, html
      assert_equal "&lt;read:true&gt;&lt;write:false&gt;", html
    end

    test "token data is empty for unrelated objects and safe for every key type" do
      assert_empty FakeBuilder.new(object: Object.new).api_key_token_data

      {
        "publishable" => :publishable,
        "secret" => :secret,
        "" => nil,
        "custom-client" => "custom-client"
      }.each do |raw_type, expected_type|
        object = FakeObject.new(persisted?: true, scopes: [], key_type: raw_type, environment: "test")
        data = FakeBuilder.new(object: object).api_key_token_data

        expected_type.nil? ? assert_nil(data[:type]) : assert_equal(expected_type, data[:type])
        assert_equal "pk_test_full", data[:full]
        assert data[:viewable]
      end
    end
  end
end
