# frozen_string_literal: true

require "test_helper"

# Writes to chosen keys, as another process would, at the moment reconcile
# locks them: after the batch selected them, before the lock. Inert unless a
# test sets changes ({ key id => attributes }).
module ChangeBeforeLock
  class << self
    attr_accessor :changes
  end

  def with_lock(*args, &block)
    attributes = ChangeBeforeLock.changes&.[](id)
    self.class.where(id: id).update_all(attributes) if attributes
    super
  end
end
ApiKeys::ApiKey.prepend(ChangeBeforeLock) unless ApiKeys::ApiKey <= ChangeBeforeLock

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

  test "a key revoked between selection and lock gains nothing" do
    survivor = @user.create_api_key!(name: "Survivor", key_type: :publishable, scopes: %w[read])
    late = @user.create_api_key!(name: "Revoked late", key_type: :publishable, scopes: %w[read])
    configure!(publishable: %w[read heartbeat], secret: %w[read write])
    ChangeBeforeLock.changes = { late.id => { revoked_at: Time.current } }

    assert_equal 1, ApiKeys.reconcile_scopes!(key_type: :publishable), "the late revocation is not counted"

    assert late.reload.revoked?, "precondition: it was revoked after being selected"
    assert_equal %w[read], late.scopes, "revoked keys are left alone"
    assert_equal %w[read heartbeat], survivor.reload.scopes
  ensure
    ChangeBeforeLock.changes = nil
  end

  test "a key retyped between selection and lock gains nothing" do
    survivor = @user.create_api_key!(name: "Survivor", key_type: :publishable, scopes: %w[read])
    retyped = @user.create_api_key!(name: "Retyped late", key_type: :publishable, scopes: %w[read])
    configure!(publishable: %w[read heartbeat], secret: %w[read write])
    ChangeBeforeLock.changes = { retyped.id => { key_type: "secret" } }

    assert_equal 1, ApiKeys.reconcile_scopes!(key_type: :publishable), "the retyped key is not counted"

    assert_equal "secret", retyped.reload.key_type, "precondition: it was retyped after being selected"
    assert_equal %w[read], retyped.scopes, "a publishable ceiling never reaches a key of another type"
    assert_equal %w[read heartbeat], survivor.reload.scopes
  ensure
    ChangeBeforeLock.changes = nil
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
