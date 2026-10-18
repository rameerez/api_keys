# frozen_string_literal: true

require "test_helper"

# Issue #28, option 2: an add-only backfill for stored-scope key types whose
# ceiling was widened. It may only ever add permissions the type already allows.
class ReconcileScopesTest < ApiKeys::Test
  def setup
    super
    @user = User.create!(name: "Reconcile Owner")
    configure!(publishable: %w[read], secret: %w[read write])
  end

  test "merges a widened ceiling into every non-revoked key of the type" do
    first = @user.create_api_key!(name: "First", key_type: :publishable, scopes: %w[read])
    second = @user.create_api_key!(name: "Second", key_type: :publishable, scopes: [])
    revoked = @user.create_api_key!(name: "Revoked", key_type: :publishable, scopes: %w[read])
    revoked.revoke!
    other_type = @user.create_api_key!(name: "Server", key_type: :secret, scopes: %w[read])
    configure!(publishable: %w[read heartbeat], secret: %w[read write heartbeat])

    assert_equal 2, ApiKeys.reconcile_scopes!(key_type: :publishable)

    assert_equal %w[read heartbeat], first.reload.scopes
    assert_equal %w[read heartbeat], second.reload.scopes
    assert first.allows_scope?("heartbeat")
    assert_equal %w[read], revoked.reload.scopes, "revoked keys are left alone"
    assert_equal %w[read], other_type.reload.scopes, "only the named type is touched"
  end

  test "is add-only and idempotent" do
    key = @user.create_api_key!(name: "Legacy Extra", key_type: :publishable, scopes: %w[read])
    key.update_column(:scopes, %w[legacy_scope])
    configure!(publishable: %w[read heartbeat], secret: %w[read write])

    assert_equal 1, ApiKeys.reconcile_scopes!(key_type: "publishable")
    assert_equal %w[legacy_scope read heartbeat], key.reload.scopes, "nothing is ever removed"
    refute key.allows_scope?("legacy_scope"), "a kept stale entry still cannot pass the ceiling"
    assert_equal 0, ApiKeys.reconcile_scopes!(key_type: :publishable)
  end

  test "refuses an unknown type or an unbounded ceiling" do
    assert_raises(ArgumentError) { ApiKeys.reconcile_scopes!(key_type: :missing) }

    ApiKeys.configuration.key_types = { secret: { prefix: "sk", permissions: :all } }
    error = assert_raises(ArgumentError) { ApiKeys.reconcile_scopes!(key_type: :secret) }
    assert_includes error.message, "finite permission ceiling"
  end

  test "never writes over damaged scopes or past the scope limit" do
    damaged = @user.create_api_key!(name: "Damaged", key_type: :publishable, scopes: %w[read])
    damaged.update_column(:scopes, { "read" => true })
    crowded = @user.create_api_key!(name: "Crowded", key_type: :publishable, scopes: %w[read])
    crowded_scopes = Array.new(ApiKeys::ApiKey::MAX_SCOPES) { |index| "legacy#{index}" }
    crowded.update_column(:scopes, crowded_scopes)
    configure!(publishable: %w[read heartbeat], secret: %w[read write])

    assert_equal 0, ApiKeys.reconcile_scopes!(key_type: :publishable)
    assert_equal({ "read" => true }, damaged.reload.scopes)
    assert_equal crowded_scopes, crowded.reload.scopes
  end

  private

  def configure!(ceilings)
    ApiKeys.configure do |config|
      config.key_types = {
        publishable: { prefix: "pk", permissions: ceilings[:publishable] },
        secret: { prefix: "sk", permissions: ceilings[:secret] }
      }
      config.environments = { test: { prefix_segment: "test" } }
      config.current_environment = -> { :test }
    end
  end
end
