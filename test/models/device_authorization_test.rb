# frozen_string_literal: true

require "test_helper"

# The device flow's model (RFC 8628): a client asks for codes, a person
# approves or denies, and the client's polls get the RFC's answers: pending,
# slow down, denied, expired, and the key once.
ActiveRecord::Schema.define do
  # A fictional owner whose has_api_keys sets a key limit.
  create_table :teams, force: :cascade do |t|
    t.string :name
  end
end

class Team < ActiveRecord::Base
  include ApiKeys::Models::Concerns::HasApiKeys
  has_api_keys max_keys: 1
end

class DeviceAuthorizationTest < ApiKeys::Test
  Authorization = ApiKeys::DeviceAuthorization
  CLIENT = "Fictional agent"

  def teardown
    Team.delete_all
    super
  end

  def setup
    super
    ApiKeys.configure do |config|
      config.default_scopes = %w[read write deploy]
      config.enable_async_operations = false
    end
    @owner = User.create!(name: "Acme")
    @person = User.create!(name: "Ada")
  end

  def request_codes(client_id: CLIENT, device_name: "build-box", scopes: %w[read write], key_type: nil)
    Authorization.request!(client_id: client_id, device_name: device_name, scopes: scopes, requested_from: "203.0.113.7",
                           key_type: key_type)
  end

  # == Request (RFC 8628 §3.1, §3.2) ==

  test "a request gives a device code and an eight-letter user code, and keeps only their digests" do
    authorization = request_codes

    assert_match(/\A[BCDFGHJKLMNPQRSTVWXZ]{4}-[BCDFGHJKLMNPQRSTVWXZ]{4}\z/, authorization.user_code)
    assert_operator authorization.device_code.length, :>=, 43, "32 random bytes"
    assert_equal Authorization.digest(authorization.device_code), authorization.device_code_digest
    assert_equal Authorization.digest(authorization.user_code.delete("-")), authorization.user_code_digest

    stored = Authorization.find(authorization.id)
    assert_nil stored.device_code, "the text is on the new instance only"
    assert_nil stored.user_code
    refute_includes stored.attributes.values.map(&:to_s), authorization.device_code
    refute_includes stored.attributes.values.map(&:to_s), authorization.user_code.delete("-")
  end

  test "a request is pending for ten minutes with a five-second interval" do
    freeze_time do
      authorization = request_codes

      assert authorization.pending?
      assert_equal 5, authorization.interval
      assert_equal 10.minutes.from_now, authorization.expires_at
      assert_equal %w[read write], authorization.scopes
      assert_equal "203.0.113.7", authorization.requested_from
    end
  end

  test "a request names its client and asks for scopes the app grants" do
    assert_raises(ActiveRecord::RecordInvalid) { request_codes(client_id: "") }
    assert_raises(ActiveRecord::RecordInvalid) { request_codes(client_id: "x" * 61) }
    assert_raises(ActiveRecord::RecordInvalid) { request_codes(device_name: "x" * 61) }
    assert_raises(ActiveRecord::RecordInvalid) { request_codes(scopes: []) }
    assert_raises(ActiveRecord::RecordInvalid) { request_codes(scopes: %w[read admin]) }
    assert_empty Authorization.all

    assert request_codes(device_name: nil, scopes: %w[deploy deploy]).persisted?
    assert_equal %w[deploy], Authorization.sole.scopes
  end

  test "without config.default_scopes the app grants no scope, so no request is valid" do
    ApiKeys.reset_configuration!

    assert_empty Authorization.grantable_scopes
    assert_raises(ActiveRecord::RecordInvalid) { request_codes(scopes: %w[read]) }
  end

  test "the user code is found in any case, with or without the dash and spaces" do
    authorization = request_codes
    code = authorization.user_code

    [code, code.downcase, code.delete("-"), " #{code.downcase.delete('-')} ", code.downcase.tr("-", " ")].each do |typed|
      assert_equal authorization, Authorization.find_undecided_by_user_code(typed), typed
    end
    assert_nil Authorization.find_undecided_by_user_code("BCDF-GHJK")
    assert_nil Authorization.find_undecided_by_user_code(nil)
  end

  test "only an undecided, unexpired request is found by its user code" do
    approved = request_codes
    expired = request_codes
    approved.approve!(@owner, by: @person)

    assert_nil Authorization.find_undecided_by_user_code(approved.user_code)
    travel Authorization::LIFETIME + 1.second do
      assert_nil Authorization.find_undecided_by_user_code(expired.user_code)
    end
  end

  test "the device code finds its request whatever its state" do
    authorization = request_codes
    authorization.deny!(by: @person)

    assert_equal authorization, Authorization.find_by_device_code(authorization.device_code)
    assert_nil Authorization.find_by_device_code("unknown")
    assert_nil Authorization.find_by_device_code(nil)
  end

  # == Decide (RFC 8628 §3.3) ==

  test "the whole flow: approval, then the key once on the first poll" do
    authorization = request_codes
    authorization.approve!(@owner, by: @person)

    assert authorization.reload.approved?
    assert_equal @owner, authorization.owner
    assert_equal @person, authorization.decided_by
    assert_not_nil authorization.decided_at
    assert_empty @owner.api_keys, "the key is made at the poll, so its token is never stored"

    poll = authorization.poll!(client_id: CLIENT)
    assert_nil poll.error
    key = poll.api_key
    assert_match(/\Aak_/, key.token)
    assert_equal "Fictional agent on build-box", key.name
    assert_equal %w[read write], key.scopes
    assert_equal @owner, key.owner
    assert authorization.reload.completed?
    assert_equal key, authorization.api_key

    again = authorization.poll!(client_id: CLIENT)
    assert_equal "invalid_grant", again.error, "the token comes once"
    assert_nil again.api_key
    assert_equal 1, @owner.api_keys.count
  end

  test "a poll from another client_id, or none, gets invalid_grant and leaves the grant to its client" do
    authorization = request_codes
    authorization.approve!(@owner, by: @person)

    ["Another agent", nil, "", " #{CLIENT}x"].each do |client_id|
      assert_equal "invalid_grant", authorization.poll!(client_id: client_id).error, client_id.inspect
    end
    assert authorization.reload.approved?
    assert_nil authorization.last_polled_at
    assert_empty @owner.api_keys

    assert authorization.poll!(client_id: " #{CLIENT} ").api_key, "the client_id is compared without outer spaces"
  end

  test "polls before the decision: pending, then slow down by five seconds when too soon" do
    authorization = request_codes

    assert_equal "authorization_pending", authorization.poll!(client_id: CLIENT).error
    assert_equal "slow_down", authorization.poll!(client_id: CLIENT).error
    assert_equal 10, authorization.reload.interval

    travel 6.seconds do
      assert_equal "slow_down", authorization.poll!(client_id: CLIENT).error, "the interval is now ten seconds"
      assert_equal 15, authorization.reload.interval
    end
    travel 22.seconds do
      assert_equal "authorization_pending", authorization.poll!(client_id: CLIENT).error
      assert_equal 15, authorization.reload.interval, "slow_down holds for all later polls"
    end
  end

  test "the first poll after the approval gets the key even when it comes soon" do
    authorization = request_codes
    authorization.poll!(client_id: CLIENT)
    authorization.approve!(@owner, by: @person)

    assert authorization.poll!(client_id: CLIENT).api_key
  end

  test "a denied request gives no key" do
    authorization = request_codes
    authorization.deny!(by: @person)

    assert authorization.reload.denied?
    assert_equal @person, authorization.decided_by
    assert_nil authorization.owner
    assert_equal "access_denied", authorization.poll!(client_id: CLIENT).error
    assert_empty ApiKeys::ApiKey.all
  end

  test "codes expire after ten minutes, approved or not, and an expired request cannot be decided" do
    pending = request_codes
    approved = request_codes(device_name: "second-box")
    approved.approve!(@owner, by: @person)

    travel Authorization::LIFETIME + 1.second do
      assert_equal "expired_token", approved.poll!(client_id: CLIENT).error
      assert_equal "expired_token", pending.poll!(client_id: CLIENT).error
      assert_raises(Authorization::Closed) { pending.approve!(@owner, by: @person) }
      assert_raises(Authorization::Closed) { pending.deny!(by: @person) }
    end
    assert pending.reload.pending?
    assert_empty ApiKeys::ApiKey.all
  end

  test "a decided request cannot be decided again" do
    approved = request_codes
    approved.approve!(@owner, by: @person)
    assert_raises(Authorization::Closed) { approved.deny!(by: @person) }
    assert_raises(Authorization::Closed) { approved.approve!(User.create!(name: "Other"), by: @person) }
    assert_equal @owner, approved.reload.owner

    denied = request_codes
    denied.deny!(by: @person)
    assert_raises(Authorization::Closed) { denied.approve!(@owner, by: @person) }
    assert denied.reload.denied?

    approved.poll!(client_id: CLIENT)
    assert_raises(Authorization::Closed) { approved.reload.approve!(@owner, by: @person) }
  end

  test "a stale copy of the request is decided against the row as it is now" do
    authorization = request_codes
    stale = Authorization.find(authorization.id)
    authorization.deny!(by: @person)

    assert_raises(Authorization::Closed) { stale.approve!(@owner, by: @person) }
    assert authorization.reload.denied?
  end

  test "an approval names a saved owner that has API keys" do
    authorization = request_codes

    assert_raises(ArgumentError) { authorization.approve!(User.new(name: "Unsaved"), by: @person) }
    assert_raises(ArgumentError) { authorization.approve!(Object.new, by: @person) }
    assert authorization.reload.pending?
  end

  test "an owner deleted after the approval gets no key" do
    authorization = request_codes
    authorization.approve!(@owner, by: @person)
    @owner.destroy!

    assert_equal "access_denied", authorization.reload.poll!(client_id: CLIENT).error
    assert_empty ApiKeys::ApiKey.all
  end

  # == The owner's key limit ==

  test "an approval for an owner at its key limit is refused, and the request stays pending" do
    team = Team.create!(name: "Acme team")
    team.create_api_key!(name: "Existing")
    authorization = request_codes

    error = assert_raises(Authorization::KeyLimitReached) { authorization.approve!(team, by: @person) }
    assert_match "revoke a key", error.message
    assert authorization.reload.pending?
    assert_nil authorization.owner
    assert_equal "authorization_pending", authorization.poll!(client_id: CLIENT).error

    team.api_keys.sole.revoke!
    authorization.approve!(team, by: @person)
    assert authorization.poll!(client_id: CLIENT).api_key
  end

  test "an approval checks the limit of the request's key type" do
    ApiKeys.configure do |config|
      config.key_types = { secret: { prefix: "sk", permissions: :all, limit: 1 } }
      config.default_key_type = :secret
    end
    @owner.create_api_key!(name: "Existing")
    authorization = request_codes(key_type: :secret)

    assert_raises(Authorization::KeyLimitReached) { authorization.approve!(@owner, by: @person) }
    assert authorization.reload.pending?
  end

  # == Key types ==

  test "with key types configured, a request names a configured type; without them, none" do
    ApiKeys.configure { |config| config.key_types = { secret: { prefix: "sk", permissions: :all } } }

    error = assert_raises(ArgumentError) { request_codes }
    assert_match "default_key_type", error.message
    assert_raises(ArgumentError) { request_codes(key_type: :publishable) }
    assert_equal "secret", request_codes(key_type: :secret).key_type

    ApiKeys.configuration.key_types = {}
    assert_raises(ArgumentError) { request_codes(key_type: :secret) }
    assert_empty Authorization.where(key_type: nil)
  end

  test "the key is of the request's type" do
    ApiKeys.configure do |config|
      config.key_types = { secret: { prefix: "sk", permissions: :all }, agent: { prefix: "ag", permissions: %w[read write] } }
      config.default_key_type = :secret
    end
    authorization = request_codes(key_type: :agent)
    authorization.approve!(@owner, by: @person)

    key = authorization.poll!(client_id: CLIENT).api_key
    assert_equal "agent", key.key_type
    assert_match(/\Aag_/, key.token)
    assert_equal %w[read write], key.scopes
  end

  test "a type with a finite ceiling grants only the scopes within it" do
    ApiKeys.configure do |config|
      config.key_types = { agent: { prefix: "ag", permissions: %w[read write] } }
    end

    assert_equal %w[read write], Authorization.grantable_scopes(:agent)
    assert_equal %w[read write deploy], Authorization.grantable_scopes
    assert_raises(ActiveRecord::RecordInvalid) { request_codes(key_type: :agent, scopes: %w[read deploy]) }
  end

  test "a ceiling type grants its whole ceiling, so the request must ask for all of it" do
    ApiKeys.configure do |config|
      config.key_types = { agent: { prefix: "ag", permissions: %w[read write], scopes: :ceiling } }
    end

    error = assert_raises(ActiveRecord::RecordInvalid) { request_codes(key_type: :agent, scopes: %w[read]) }
    assert_match "every permission", error.message
    assert_empty Authorization.all

    authorization = request_codes(key_type: :agent, scopes: %w[read write])
    authorization.approve!(@owner, by: @person)
    key = authorization.poll!(client_id: CLIENT).api_key
    assert key.allows_scope?("write")
    assert_equal %w[read write], authorization.granted_scopes
  end

  test "a ceiling widened after the request: the approval is refused, and a poll makes no key" do
    ApiKeys.configure do |config|
      config.key_types = { agent: { prefix: "ag", permissions: %w[read write], scopes: :ceiling } }
    end
    before_approval = request_codes(key_type: :agent, scopes: %w[read write])
    after_approval = request_codes(key_type: :agent, scopes: %w[read write])
    after_approval.approve!(@owner, by: @person)

    ApiKeys.configuration.key_types = { agent: { prefix: "ag", permissions: %w[read write deploy], scopes: :ceiling } }

    assert_raises(ActiveRecord::RecordInvalid) { before_approval.approve!(@owner, by: @person) }
    assert before_approval.reload.pending?
    assert_equal "invalid_scope", after_approval.poll!(client_id: CLIENT).error, "the key would also authorize deploy"
    assert_empty ApiKeys::ApiKey.all
  end

  test "an owner that reaches its limit after the approval: the poll waits, and never raises" do
    team = Team.create!(name: "Acme team")
    authorization = request_codes
    authorization.approve!(team, by: @person)
    team.create_api_key!(name: "Made since the approval")

    assert_equal "authorization_pending", authorization.poll!(client_id: CLIENT).error
    assert authorization.reload.approved?
    assert_nil authorization.api_key
    assert_equal 1, team.api_keys.count, "nothing is kept of the failed key"

    travel 6.seconds do
      team.api_keys.sole.revoke!
      key = authorization.poll!(client_id: CLIENT).api_key
      assert_equal "Fictional agent on build-box", key.name
      assert authorization.reload.completed?
    end
  end

  test "a poll never raises for a key that cannot be made, whatever the reason" do
    authorization = request_codes
    authorization.approve!(@owner, by: @person)

    [ActiveRecord::RecordInvalid.new(ApiKeys::ApiKey.new), ArgumentError.new("key_type is required"),
     ApiKeys::Errors::CreatedByMigrationRequiredError.new, ApiKeys::Error.new("prefix")].each do |error|
      travel 30.seconds # each poll keeps to the interval
      User.any_instance.stubs(:create_api_key!).raises(error)
      assert_equal "authorization_pending", authorization.poll!(client_id: CLIENT).error, error.class.name
      User.any_instance.unstub(:create_api_key!)
      assert authorization.reload.approved?
    end

    assert authorization.poll!(client_id: CLIENT).api_key
  ensure
    travel_back
  end

  test "a poll after the app stopped granting a scope does not raise" do
    authorization = request_codes(scopes: %w[read deploy])
    ApiKeys.configuration.default_scopes = %w[read]

    assert_equal "authorization_pending", authorization.poll!(client_id: CLIENT).error
  end

  # == The key's name ==

  test "the key is named after the client and its device" do
    assert_equal "Fictional agent on build-box", request_codes.key_name
    assert_equal "Fictional agent", request_codes(device_name: nil).key_name
    assert_equal "Fictional agent", request_codes(device_name: "").key_name
  end

  test "characters a key name cannot hold become hyphens, and the name keeps to sixty characters" do
    named = request_codes(client_id: "codex-cli/1.2 (beta)", device_name: "Ada's MacBook.local")
    assert_equal "codex-cli-1-2 -beta- on Ada-s MacBook-local", named.key_name

    long = request_codes(client_id: "a" * 60, device_name: "b" * 60)
    assert_equal 60, long.key_name.length

    [named, long].each do |authorization|
      authorization.approve!(@owner, by: @person)
      key = authorization.poll!(client_id: authorization.client_id).api_key
      assert key.persisted?, authorization.key_name
      assert_equal authorization.key_name, key.name
    end
  end

  # == Housekeeping ==

  test "prune! deletes the requests that expired more than a day ago" do
    old = request_codes
    recent = request_codes

    travel 1.day + Authorization::LIFETIME + 1.second do
      recent.update_columns(expires_at: 1.hour.ago)
      assert_equal 1, Authorization.prune!
    end
    assert_equal [recent], Authorization.all.to_a
    assert_raises(ActiveRecord::RecordNotFound) { old.reload }
  end

  test "a deleted key leaves its completed request in place without it" do
    authorization = request_codes
    authorization.approve!(@owner, by: @person)
    key = authorization.poll!(client_id: CLIENT).api_key

    ApiKeys::ApiKey.where(id: key.id).delete_all

    assert_nil authorization.reload.api_key_id
    assert authorization.completed?
  end
end
