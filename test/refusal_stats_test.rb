# frozen_string_literal: true

require "test_helper"
require "active_job"

# Issue #38: refused-but-identified traffic gets its own columns, stamped
# through the same async stats job as last_used_at. A refusal is not a use:
# last_used_at and requests_count must never move because of one, since
# downstream integrations detect "first working request" from last_used_at.
class RefusalStatsTest < ApiKeys::Test
  include ActiveJob::TestHelper

  class FakeRequest
    attr_reader :headers, :query_parameters, :protocol, :uuid, :remote_ip

    def initialize(token: nil, origin: nil, remote_ip: "203.0.113.7")
      @headers = {}
      @headers["Authorization"] = "Bearer #{token}" if token
      @headers["Origin"] = origin if origin
      @query_parameters = {}
      @protocol = "https://"
      @remote_ip = remote_ip
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
    ApiKeys.configure do |config|
      config.enable_async_operations = true
      config.track_requests_count = true
    end
    @user = User.create!(name: "Refusal Owner")
  end

  # =============================================================================
  # UpdateStatsJob: the refusal half
  # =============================================================================

  test "a refusal stamps when and why, and never touches usage" do
    key = @user.create_api_key!(name: "Refused")
    refused_at = Time.current

    ApiKeys::Jobs::UpdateStatsJob.perform_now(key.id, refused_at, refusal_code: "origin_not_allowed")

    key.reload
    assert_in_delta refused_at.to_f, key.last_refused_at.to_f, 1
    assert_equal "origin_not_allowed", key.last_refusal_code
    assert_equal 1, key.refusals_count
    assert_nil key.last_used_at, "a refused request must never look like a working integration"
    assert_equal 0, key.requests_count
  end

  test "refusals_count is kept under the same switch as requests_count" do
    ApiKeys.configuration.track_requests_count = false
    key = @user.create_api_key!(name: "Uncounted")

    ApiKeys::Jobs::UpdateStatsJob.perform_now(key.id, Time.current, refusal_code: "ip_not_allowed")

    key.reload
    refute_nil key.last_refused_at
    assert_equal 0, key.refusals_count
  end

  test "a refusal marker of any shape never counts as a use" do
    key = @user.create_api_key!(name: "Markers")

    ["", "bogus", :bogus, false, "invalid_token", "missing_token", "insecure_connection"].each do |marker|
      ApiKeys::Jobs::UpdateStatsJob.perform_now(key.id, Time.current, refusal_code: marker)

      key.reload
      assert_nil key.last_used_at, "#{marker.inspect} moved last_used_at"
      assert_equal 0, key.requests_count, "#{marker.inspect} counted a request"
      assert_nil key.last_refused_at, "#{marker.inspect} is not an identified refusal code"
      assert_equal 0, key.refusals_count
    end
  end

  test "a use never moves the refusal columns" do
    key = @user.create_api_key!(name: "Used")

    ApiKeys::Jobs::UpdateStatsJob.perform_now(key.id, Time.current)

    key.reload
    refute_nil key.last_used_at, "the legacy two-argument job still records a use"
    assert_nil key.last_refused_at
    assert_nil key.last_refusal_code
    assert_equal 0, key.refusals_count
  end

  test "out-of-order refusals keep the newest timestamp paired with its code" do
    key = @user.create_api_key!(name: "Ordered")
    newest = Time.current

    ApiKeys::Jobs::UpdateStatsJob.perform_now(key.id, newest, refusal_code: "origin_not_allowed")
    ApiKeys::Jobs::UpdateStatsJob.perform_now(key.id, 1.hour.ago, refusal_code: "ip_not_allowed")

    key.reload
    assert_in_delta newest.to_f, key.last_refused_at.to_f, 1
    assert_equal "origin_not_allowed", key.last_refusal_code
  end

  test "future refusal timestamps are rejected" do
    key = @user.create_api_key!(name: "Future")

    ApiKeys::Jobs::UpdateStatsJob.perform_now(key.id, 1.day.from_now, refusal_code: "origin_not_allowed")

    assert_nil key.reload.last_refused_at
    assert_equal 0, key.refusals_count
  end

  # =============================================================================
  # authenticate_api_key!: which refusals are stamped
  # =============================================================================

  test "every identified refusal is stamped, and none moves last_used_at" do
    scenarios = {
      "revoked_key" => -> { revoked_key },
      "expired_key" => -> { expired_key },
      "origin_not_allowed" => -> { [@user.create_api_key!(name: "Origin", allowed_origins: "example.com"), {}] },
      "ip_not_allowed" => -> { [@user.create_api_key!(name: "Address", allowed_ips: "10.0.0.0/8"), {}] },
      "restriction_misconfigured" => -> { misconfigured_restrictions_key },
      "missing_scope" => -> { [@user.create_api_key!(name: "Read Only", scopes: %w[read]), { scope: "write" }] }
    }

    scenarios.each do |code, build|
      key, options = build.call
      controller = perform_enqueued_jobs { authenticate(key.token, origin: "https://elsewhere.example", **options) }

      assert_equal code.to_sym, controller.rendered[:json][:error]
      key.reload
      assert_equal code, key.last_refusal_code, "#{code} was not stamped"
      refute_nil key.last_refused_at
      assert_equal 1, key.refusals_count
      assert_nil key.last_used_at, "#{code} moved last_used_at"
      assert_equal 0, key.requests_count, "#{code} counted a request"
    end
  end

  test "environment and key type refusals are stamped" do
    configure_key_types!
    mismatched = @user.create_api_key!(name: "Test Key", key_type: :secret, environment: :test)
    retired = @user.create_api_key!(name: "Retired", key_type: :retired)
    staging = @user.create_api_key!(name: "Staging", key_type: :secret, environment: :staging)
    staging_token = staging.token
    ApiKeys.configuration.environments = { test: { prefix_segment: "test" }, live: { prefix_segment: "live" } }
    perform_enqueued_jobs { authenticate(staging_token) }
    assert_equal "unknown_environment", staging.reload.last_refusal_code
    ApiKeys.configure do |config|
      config.strict_environment_isolation = true
      config.current_environment = -> { :live }
    end

    perform_enqueued_jobs { authenticate(mismatched.token) }
    assert_equal "environment_mismatch", mismatched.reload.last_refusal_code

    ApiKeys.configuration.key_types = { secret: { prefix: "sk", permissions: :all } }
    perform_enqueued_jobs { authenticate(retired.token) }
    assert_equal "unknown_key_type", retired.reload.last_refusal_code
    assert_nil retired.last_used_at
  end

  test "lookup failures stamp nothing, including a forgery of a real key's prefix and last four" do
    key = @user.create_api_key!(name: "Target")
    forged = key.token.dup
    forged[-6] = forged[-6] == "A" ? "B" : "A"

    [forged, "ak_never_minted", nil].each do |token|
      controller = authenticate(token)

      assert_equal :unauthorized, controller.rendered[:status]
      assert_no_refusal_jobs
    end
    assert_nil key.reload.last_refused_at, "only a verified token can be attributed to a key"
  end

  test "only identified refusal codes can be stamped, whatever the caller passes" do
    key = @user.create_api_key!(name: "Allowlisted")
    controller = FakeController.new(FakeRequest.new(token: key.token))

    %i[invalid_token missing_token insecure_connection made_up].each do |code|
      controller.send(:record_key_refusal, key, code)
    end
    controller.send(:record_key_refusal, nil, :origin_not_allowed)

    assert_no_refusal_jobs
  end

  test "refusals are debounced exactly like last_used_at" do
    ApiKeys.configure do |config|
      config.track_requests_count = false
      config.stats_update_interval = 1.minute
    end
    key = @user.create_api_key!(name: "Hammered", allowed_origins: "example.com")
    key.update_column(:last_refused_at, 30.seconds.ago)

    authenticate(key.token, origin: "https://elsewhere.example")
    assert_no_refusal_jobs

    key.update_column(:last_refused_at, 2.minutes.ago)
    authenticate(key.token, origin: "https://elsewhere.example")
    assert_equal 1, refusal_jobs.length
  end

  test "exact counting stamps every refusal" do
    ApiKeys.configuration.stats_update_interval = 1.hour
    key = @user.create_api_key!(name: "Counted", allowed_origins: "example.com")

    perform_enqueued_jobs do
      2.times { authenticate(key.token, origin: "https://elsewhere.example") }
    end

    assert_equal 2, key.reload.refusals_count
  end

  test "a working request after refusals moves only the usage columns" do
    key = @user.create_api_key!(name: "Mixed", allowed_origins: "example.com")
    token = key.token

    perform_enqueued_jobs { authenticate(token, origin: "https://elsewhere.example") }
    refused_at = key.reload.last_refused_at
    perform_enqueued_jobs { authenticate(token, origin: "https://example.com") }

    key.reload
    refute_nil key.last_used_at
    assert_equal 1, key.requests_count
    assert_equal 1, key.refusals_count
    assert_equal refused_at, key.last_refused_at
  end

  test "disabling async operations stamps nothing" do
    ApiKeys.configuration.enable_async_operations = false
    key = @user.create_api_key!(name: "Quiet", allowed_origins: "example.com")

    authenticate(key.token, origin: "https://elsewhere.example")

    assert_no_refusal_jobs
  end

  test "a failing refusal enqueue changes neither the response nor the callback" do
    ApiKeys.configuration.after_authentication = ->(context) { context }
    key = @user.create_api_key!(name: "Broken Queue", allowed_origins: "example.com")
    ApiKeys::Jobs::UpdateStatsJob.stubs(:perform_later).raises(StandardError, "queue down")

    controller = authenticate(key.token, origin: "https://elsewhere.example")

    assert_equal :forbidden, controller.rendered[:status]
    assert_equal :origin_not_allowed, controller.rendered[:json][:error]
    after_jobs = enqueued_jobs.select { |job| job[:job] == ApiKeys::Jobs::CallbacksJob }
    assert_equal 1, after_jobs.length
    assert_equal key.id, ActiveJob::Arguments.deserialize(after_jobs.first[:args]).last[:api_key_id]
  end

  # =============================================================================
  # An installation that has not migrated yet
  # =============================================================================

  test "without the refusal columns, authentication keeps working and nothing raises" do
    key = @user.create_api_key!(name: "Unmigrated", allowed_origins: "example.com")
    token = key.token
    ApiKeys::Jobs::UpdateStatsJob.any_instance.expects(:log_error).never

    RefusalStatsSchema.without_columns do
      key = ApiKeys::ApiKey.find(key.id)
      refute ApiKeys::ApiKey.refusal_stats_columns?
      refute key.has_attribute?(:last_refused_at), "the columns really are gone"
      assert_nil key.last_refused_at
      assert_equal 0, key.refusals_count
      assert_nil key.last_refusal_code

      allowed = perform_enqueued_jobs { authenticate(token, origin: "https://example.com") }
      assert_nil allowed.rendered
      refute_nil key.reload.last_used_at

      refused = authenticate(token, origin: "https://elsewhere.example")
      assert_equal :origin_not_allowed, refused.rendered[:json][:error]
      assert_no_refusal_jobs

      # A refusal job enqueued before the columns went away is a quiet no-op.
      ApiKeys::Jobs::UpdateStatsJob.perform_now(key.id, Time.current, refusal_code: "origin_not_allowed")
    end
  end

  # =============================================================================
  # Reasons
  # =============================================================================

  test "every stampable code has a plain-language reason" do
    assert_equal ApiKeys::ApiKey::REFUSAL_CODES.sort, ApiKeys::Helpers::ViewHelpers::REFUSAL_REASONS.keys.sort
  end

  test "the reason helper explains a refusal without echoing the stored code" do
    helper = Object.new.extend(ApiKeys::Helpers::ViewHelpers)
    key = @user.create_api_key!(name: "Explained")

    assert_nil helper.api_key_refusal_reason(key)

    key.update_columns(last_refused_at: Time.current, last_refusal_code: "origin_not_allowed")
    assert_equal "the request came from a web origin the key does not allow", helper.api_key_refusal_reason(key)

    key.update_columns(last_refusal_code: "<script>alert(1)</script>")
    assert_equal ApiKeys::Helpers::ViewHelpers::UNKNOWN_REFUSAL_REASON, helper.api_key_refusal_reason(key)
  end

  private

  def authenticate(token, scope: nil, **request_options)
    controller = FakeController.new(FakeRequest.new(token: token, **request_options))
    controller.send(:authenticate_api_key!, scope: scope)
    controller
  end

  def refusal_jobs
    enqueued_jobs.select do |job|
      job[:job] == ApiKeys::Jobs::UpdateStatsJob && ActiveJob::Arguments.deserialize(job[:args]).last.is_a?(Hash)
    end
  end

  def assert_no_refusal_jobs
    assert_empty refusal_jobs
  end

  def revoked_key
    key = @user.create_api_key!(name: "Revoked")
    token = key.token
    key.revoke!
    key.instance_variable_set(:@token, token)
    [key, {}]
  end

  def expired_key
    key = @user.create_api_key!(name: "Expired", expires_at: 1.day.from_now)
    key.update_column(:expires_at, 1.minute.ago)
    [key, {}]
  end

  def misconfigured_restrictions_key
    key = @user.create_api_key!(name: "Damaged Policy")
    key.update_column(:restrictions, { "origins" => ["*"] })
    [key, {}]
  end

  def configure_key_types!
    ApiKeys.configure do |config|
      config.key_types = {
        secret: { prefix: "sk", permissions: :all },
        retired: { prefix: "rt", permissions: %w[read] }
      }
      config.environments = { test: { prefix_segment: "test" }, live: { prefix_segment: "live" },
                              staging: { prefix_segment: "stg" } }
      config.current_environment = -> { :test }
    end
  end
end
