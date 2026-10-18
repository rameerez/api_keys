# frozen_string_literal: true

require "test_helper"
require "active_job"

# Issue #28: keys store their scopes at creation, so widening a key type's
# `permissions:` ceiling never reached existing keys, which then 403ed the new
# endpoints silently. `scopes: :ceiling` makes the live ceiling the contract
# for a key type that opts in. Everything else must behave exactly as before,
# and nothing here may widen a key of a type that did not opt in.
class CeilingScopesTest < ApiKeys::Test
  class FakeRequest
    attr_reader :headers, :query_parameters, :protocol, :uuid, :remote_ip

    def initialize(token:)
      @headers = { "Authorization" => "Bearer #{token}" }
      @query_parameters = {}
      @protocol = "https://"
      @remote_ip = "203.0.113.7"
      @uuid = SecureRandom.uuid
    end
  end

  class FakeController
    include ApiKeys::Authentication

    attr_reader :rendered, :request

    def initialize(request)
      @request = request
      @rendered = nil
    end

    def render(json:, status:)
      @rendered = { json: json, status: status }
    end
  end

  def setup
    super
    ApiKeys.configure { |config| config.enable_async_operations = false }
    @user = User.create!(name: "Ceiling Owner")
  end

  # =============================================================================
  # Configuration
  # =============================================================================

  test "a key type may opt into ceiling-authoritative scopes" do
    configure!(sdk: { permissions: %w[read heartbeat], scopes: :ceiling })

    assert_equal :ceiling, ApiKeys.configuration.key_types[:sdk][:scopes]
  end

  test "the scope source accepts :stored, :ceiling and their strings" do
    assert_nothing_raised do
      configure!(a: { permissions: %w[read], scopes: :stored },
                 b: { permissions: %w[read], scopes: "ceiling" },
                 c: { permissions: :all, scopes: "stored" })
    end
  end

  test "scopes: :ceiling refuses an unbounded or empty ceiling" do
    # Against :all, every existing key of the type would become all-powerful.
    error = assert_raises(ArgumentError) { configure!(sdk: { permissions: :all, scopes: :ceiling }) }
    assert_includes error.message, "finite, non-empty"

    assert_raises(ArgumentError) { configure!(sdk: { permissions: [], scopes: :ceiling }) }
  end

  test "an unknown scope source is a configuration error, never a silent default" do
    [:celing, :all, true, nil, 1, ["ceiling"]].each do |source|
      assert_raises(ArgumentError, "expected #{source.inspect} to be rejected") do
        configure!(sdk: { permissions: %w[read], scopes: source })
      end
    end
  end

  # =============================================================================
  # Authorization
  # =============================================================================

  test "the bug: widening an ordinary type's ceiling never reaches existing keys" do
    configure!(sdk: { permissions: %w[read] })
    key = @user.create_api_key!(name: "Shipped SDK", key_type: :sdk, scopes: %w[read])

    configure!(sdk: { permissions: %w[read heartbeat] })

    refute key.reload.allows_scope?("heartbeat"),
           "stored-scope types keep the snapshot they were created with (documented in the README)"
  end

  test "widening a ceiling type's permissions reaches every existing key" do
    configure!(sdk: { permissions: %w[read], scopes: :ceiling })
    key = @user.create_api_key!(name: "Shipped SDK", key_type: :sdk, scopes: %w[read])

    configure!(sdk: { permissions: %w[read heartbeat], scopes: :ceiling })

    assert key.reload.allows_scope?("heartbeat")
    assert key.allows_permission?("heartbeat")
    assert_equal %w[read], key.scopes, "stored scopes stay as metadata; nothing is rewritten"
  end

  test "authenticate_api_key!(scope:) follows the live ceiling end to end" do
    configure!(sdk: { permissions: %w[read], scopes: :ceiling })
    key = @user.create_api_key!(name: "Shipped SDK", key_type: :sdk)
    token = key.token

    refused = authenticate(token, scope: "heartbeat")
    assert_equal :forbidden, refused.rendered[:status]
    assert_equal :missing_scope, refused.rendered[:json][:error]

    configure!(sdk: { permissions: %w[read heartbeat], scopes: :ceiling })

    allowed = authenticate(token, scope: %w[read heartbeat])
    assert_nil allowed.rendered
    assert_equal key.id, allowed.send(:current_api_key).id
  end

  test "narrowing a ceiling type's permissions takes effect on the next request" do
    configure!(sdk: { permissions: %w[read write], scopes: :ceiling })
    key = @user.create_api_key!(name: "Shipped SDK", key_type: :sdk, scopes: %w[read write])
    token = key.token
    assert_nil authenticate(token, scope: "write").rendered

    configure!(sdk: { permissions: %w[read], scopes: :ceiling })

    refused = authenticate(token, scope: "write")
    assert_equal :forbidden, refused.rendered[:status]
    refute key.reload.allows_scope?("write"), "a stored scope must not outlive the ceiling that granted it"
    assert key.allows_scope?("read")
  end

  test "a ceiling key is authorized for exactly the ceiling, whatever it stored" do
    configure!(sdk: { permissions: %w[read heartbeat], scopes: :ceiling })
    empty = @user.create_api_key!(name: "Empty", key_type: :sdk, scopes: [])

    assert empty.allows_scope?("read"), "on a ceiling type the ceiling is the contract, even for an empty list"
    assert empty.allows_scope?(:heartbeat)
    refute empty.allows_scope?("admin")
    refute empty.allows_scope?(""), "a blank requirement is never granted"
    refute empty.allows_scope?(nil)
  end

  test "a stored scope outside the ceiling never authorizes a ceiling key" do
    configure!(sdk: { permissions: %w[read], scopes: :ceiling })
    key = @user.create_api_key!(name: "Tampered", key_type: :sdk, scopes: %w[read])

    key.update_column(:scopes, %w[read admin])

    refute key.reload.allows_scope?("admin")
  end

  test "damaged stored scopes fail closed on a ceiling key" do
    configure!(sdk: { permissions: %w[read], scopes: :ceiling })
    key = @user.create_api_key!(name: "Damaged", key_type: :sdk, scopes: %w[read])

    [{ "read" => true }, "read", ["read", ""], ["read", "has space"], ["read", 7]].each do |damaged|
      key.update_column(:scopes, damaged)

      refute key.reload.allows_scope?("read"), "expected #{damaged.inspect} to deny"
    end
  end

  test "a type that did not opt in is never widened by its ceiling" do
    configure!(sdk: { permissions: %w[read heartbeat], scopes: :ceiling },
               secret: { permissions: %w[read write admin] })
    secret = @user.create_api_key!(name: "Server", key_type: :secret, scopes: %w[read])

    refute secret.scopes_follow_ceiling?
    refute secret.allows_scope?("write")
    refute secret.allows_scope?("heartbeat")
    assert_equal :forbidden, authenticate(secret.token, scope: "write").rendered[:status]
  end

  test "untyped legacy keys never follow a ceiling" do
    legacy = @user.create_api_key!(name: "Legacy", scopes: %w[read])
    configure!(sdk: { permissions: %w[read write], scopes: :ceiling })

    refute legacy.reload.scopes_follow_ceiling?
    refute legacy.allows_scope?("write")
  end

  test "a key whose type no longer exists behaves exactly as before: refused" do
    configure!(sdk: { permissions: %w[read], scopes: :ceiling })
    key = @user.create_api_key!(name: "Retired", key_type: :sdk)
    token = key.token

    configure!(other: { permissions: %w[read], scopes: :ceiling })

    refute key.reload.scopes_follow_ceiling?
    refute key.allows_scope?("read")
    assert_equal :unknown_key_type, authenticate(token, scope: "read").rendered[:json][:error]
  end

  test "opting out reverts to the stored scopes, capped by the ceiling" do
    configure!(sdk: { permissions: %w[read write], scopes: :ceiling })
    key = @user.create_api_key!(name: "Opt Out", key_type: :sdk, scopes: %w[read])
    assert key.allows_scope?("write")

    configure!(sdk: { permissions: %w[read write] })

    refute key.reload.scopes_follow_ceiling?
    refute key.allows_scope?("write"), "removing scopes: :ceiling can only narrow"
    assert key.allows_scope?("read")
  end

  test "an unbounded ceiling never becomes the contract, even if validation was bypassed" do
    configure!(sdk: { permissions: %w[read], scopes: :ceiling })
    key = @user.create_api_key!(name: "Bypassed", key_type: :sdk, scopes: %w[read])
    # Simulate a configuration produced without the validating writer.
    ApiKeys.configuration.instance_variable_set(
      :@key_types, { sdk: { prefix: "sdk", permissions: :all, scopes: :ceiling } }.freeze
    )

    refute key.reload.scopes_follow_ceiling?
    refute key.allows_scope?("admin"), "falls back to stored scopes, which never held admin"
    assert key.allows_scope?("read")
    refute ApiKeys::ApiKey.scopes_follow_ceiling_for?(permissions: :all, scopes: :ceiling)
    refute ApiKeys::ApiKey.scopes_follow_ceiling_for?(permissions: [], scopes: :ceiling)
    refute ApiKeys::ApiKey.scopes_follow_ceiling_for?(nil)
  end

  # =============================================================================
  # Writes and lifecycle
  # =============================================================================

  test "users still cannot store a scope above the ceiling" do
    configure!(sdk: { permissions: %w[read], scopes: :ceiling })
    key = @user.create_api_key!(name: "Curated", key_type: :sdk, scopes: %w[read admin])

    assert_equal %w[read], key.scopes, "create_api_key! filters to the ceiling as before"
    refute key.update(scopes: %w[read admin])
    assert_includes key.errors[:scopes].join, "permission ceiling"

    direct = ApiKeys::ApiKey.new(owner: @user, name: "Direct", key_type: "sdk", environment: "test",
                                 scopes: %w[admin])
    refute direct.valid?
  end

  test "narrowing a ceiling leaves existing keys editable, so restrictions can still be tightened" do
    configure!(sdk: { permissions: %w[read write], scopes: :ceiling })
    key = @user.create_api_key!(name: "Widget", key_type: :sdk, scopes: %w[read write])

    configure!(sdk: { permissions: %w[read], scopes: :ceiling })
    key.reload

    assert key.update(name: "Renamed", allowed_origins: "example.com"), key.errors.full_messages.join(", ")
    assert_equal ["example.com"], key.reload.allowed_origins
    refute key.update(scopes: %w[write]), "any write to the scopes is still held to the current ceiling"
    assert_includes key.errors[:scopes].join, "permission ceiling"

    key.reload.scopes << "admin"
    refute key.valid?, "an in-place mutation of the stored list is a write too"
  end

  test "narrowing an ordinary type's ceiling still blocks saving its stale keys" do
    configure!(sdk: { permissions: %w[read write] })
    key = @user.create_api_key!(name: "Ordinary", key_type: :sdk, scopes: %w[read write])

    configure!(sdk: { permissions: %w[read] })

    refute key.reload.update(name: "Renamed"), "the relaxation is scoped to ceiling types only"
  end

  private

  def configure!(types)
    ApiKeys.configure do |config|
      config.key_types = types.each_with_index.to_h do |(name, settings), index|
        [name, { prefix: "#{name.to_s.delete('_')[0, 6]}#{index}" }.merge(settings)]
      end
      config.environments = { test: { prefix_segment: "test" } }
      config.current_environment = -> { :test }
    end
  end

  def authenticate(token, scope: nil)
    controller = FakeController.new(FakeRequest.new(token: token))
    controller.send(:authenticate_api_key!, scope: scope)
    controller
  end
end
