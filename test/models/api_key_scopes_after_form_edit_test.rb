# frozen_string_literal: true

require "test_helper"

module ApiKeys
  # ApiKey#scopes_after_form_edit: the dashboard's edit rule for forms that
  # offer only some scopes, public for host forms.
  class ApiKeyScopesAfterFormEditTest < ApiKeys::Test
    def setup
      super
      @user = User.create!(name: "Form Owner")
      configure_types(secret: %w[read write admin])
    end

    test "offered scopes follow their boxes and every other held scope is kept" do
      key = @user.create_api_key!(name: "Mixed", key_type: :secret, scopes: %w[read admin])

      result = key.scopes_after_form_edit(offered: %w[read write], checked: ["", "write"])

      assert_equal %w[admin write], result
      assert_equal %w[read admin], key.scopes, "it only computes the list"
      assert key.update(scopes: result)
      assert_equal %w[admin write], key.reload.scopes
    end

    test "clearing every offered box removes only the offered scopes" do
      key = @user.create_api_key!(name: "Clear", key_type: :secret, scopes: %w[read write admin])

      assert_equal %w[admin], key.scopes_after_form_edit(offered: %w[read write], checked: [""])
    end

    test "a submitted value that was never offered is ignored" do
      key = @user.create_api_key!(name: "Reader", key_type: :secret, scopes: %w[read])

      result = key.scopes_after_form_edit(offered: %w[read write], checked: %w[read admin write])

      assert_equal %w[read write], result
      refute_includes result, "admin"
    end

    test "symbols and strings are interchangeable" do
      key = @user.create_api_key!(name: "Symbols", key_type: :secret, scopes: %w[read])

      assert_equal %w[read write], key.scopes_after_form_edit(offered: %i[read write], checked: %i[read write])
    end

    test "held scopes outside a narrowed ceiling are dropped, offered or not" do
      key = @user.create_api_key!(name: "Wide", key_type: :secret, scopes: %w[read write admin])
      configure_types(secret: %w[read])
      key = ApiKey.find(key.id)

      result = key.scopes_after_form_edit(offered: %w[read write], checked: %w[read write])

      assert_equal %w[read], result, "write is offered and checked, admin is unoffered; the ceiling excludes both"
      assert key.update(scopes: result)
    end

    test "a newly checked scope outside the ceiling is kept so validation refuses it" do
      configure_types(secret: %w[read write])
      key = @user.create_api_key!(name: "Reader", key_type: :secret, scopes: %w[read])

      result = key.scopes_after_form_edit(offered: %w[read write admin], checked: %w[read admin])

      assert_equal %w[read admin], result
      refute key.update(scopes: result)
      assert_equal %w[read], key.reload.scopes
    end

    test "checked: nil grants and removes nothing except scopes outside the ceiling" do
      key = @user.create_api_key!(name: "No boxes", key_type: :secret, scopes: %w[read admin])

      assert_equal %w[read admin], key.scopes_after_form_edit(offered: %w[read write], checked: nil)

      configure_types(secret: %w[read write])
      key = ApiKey.find(key.id)
      assert_equal %w[read], key.scopes_after_form_edit(offered: %w[read write], checked: nil)
    end

    test "a scopes: :ceiling key gets its stored scopes back unchanged" do
      configure_types(secret: %w[read write admin], sdk: %w[read write])
      key = @user.create_api_key!(name: "SDK", key_type: :sdk, scopes: %w[read write])
      configure_types(secret: %w[read write admin], sdk: %w[read])
      key = ApiKey.find(key.id)

      [[""], %w[admin], nil, %w[read]].each do |checked|
        result = key.scopes_after_form_edit(offered: %w[read write admin], checked: checked)
        assert_equal %w[read write], result, checked.inspect
        refute_same key.scopes, result, "a copy, so the caller cannot mutate the key through it"
      end
      key.update!(name: "SDK renamed", scopes: key.scopes_after_form_edit(offered: %w[read], checked: [""]))
      assert_equal %w[read write], key.reload.scopes
    end

    test "malformed arguments are refused instead of guessed at" do
      key = @user.create_api_key!(name: "Strict", key_type: :secret, scopes: %w[read])

      assert_raises(ArgumentError) { key.scopes_after_form_edit(offered: "read", checked: %w[read]) }
      assert_raises(ArgumentError) { key.scopes_after_form_edit(offered: nil, checked: %w[read]) }
      assert_raises(ArgumentError) { key.scopes_after_form_edit(offered: %w[read write], checked: "write") }
      assert_raises(ArgumentError) { key.scopes_after_form_edit(offered: %w[read write], checked: { "0" => "write" }) }
    end

    test "nested or non-string checked values never match an offered scope" do
      key = @user.create_api_key!(name: "Nested", key_type: :secret, scopes: %w[read])

      result = key.scopes_after_form_edit(offered: %w[read write], checked: ["read", ["write"], { "write" => "1" }, 1])

      assert_equal %w[read], result
    end

    private

    def configure_types(secret:, sdk: nil)
      types = { secret: { prefix: "sk", permissions: secret } }
      types[:sdk] = { prefix: "sdk", permissions: sdk, scopes: :ceiling } if sdk
      ApiKeys.configure do |config|
        config.key_types = types
        config.environments = { test: { prefix_segment: "test" } }
        config.current_environment = :test
      end
    end
  end
end
