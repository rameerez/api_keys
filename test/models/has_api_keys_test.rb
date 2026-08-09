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
