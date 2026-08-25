# frozen_string_literal: true

require "test_helper"
require "active_job"

# End-to-end coverage for request restrictions: the authenticator enforcement
# point, the 403 the controller concern renders, and the model/configuration
# surface that gets restrictions onto a key in the first place.
class RequestRestrictionsTest < ApiKeys::Test
  # Stands in for ActionDispatch::Request. The authenticator only ever asks a
  # request for headers, query parameters, protocol, uuid, and remote_ip.
  class FakeRequest
    attr_reader :headers, :query_parameters, :protocol, :uuid, :remote_ip

    def initialize(token: nil, origin: nil, referer: nil, remote_ip: "203.0.113.7", headers: {})
      @headers = {}
      @headers["Authorization"] = "Bearer #{token}" if token
      @headers["Origin"] = origin unless origin.nil?
      @headers["Referer"] = referer unless referer.nil?
      @headers.merge!(headers)
      @query_parameters = {}
      @protocol = "https://"
      @remote_ip = remote_ip
      @uuid = SecureRandom.uuid
    end
  end

  # Minimal controller-like object including the authentication concern, so the
  # HTTP status mapping is exercised the way a host application sees it.
  class FakeController
    include ApiKeys::Authentication

    attr_reader :rendered

    def initialize(request)
      @request = request
      @rendered = nil
    end

    attr_reader :request

    def render(json:, status:)
      @rendered = { json: json, status: status }
    end
  end

  # A cache that behaves like Rails.cache so the token-cache hit path is real.
  class FakeCache
    def initialize
      @store = {}
    end

    def read(key)
      @store[key]
    end

    def write(key, value, **_options)
      @store[key] = value
      true
    end

    def delete(key)
      @store.delete(key)
    end
  end

  def setup
    super
    ApiKeys.configure { |config| config.enable_async_operations = false }
    @user = User.create!(name: "Restrictions Owner")
  end

  # Creates a key and returns [key, plaintext_token].
  def create_key(**attributes)
    key = ApiKeys::ApiKey.create!(owner: @user, name: "Restricted Key", **attributes)
    [ApiKeys::ApiKey.find(key.id), key.token]
  end

  def authenticate(token:, **request_options)
    ApiKeys::Services::Authenticator.call(FakeRequest.new(token: token, **request_options))
  end

  def render_authentication(token:, **request_options)
    controller = FakeController.new(FakeRequest.new(token: token, **request_options))
    controller.send(:authenticate_api_key!)
    controller
  end

  # =============================================================================
  # Authenticator: origins
  # =============================================================================

  test "an unrestricted key authenticates from anywhere" do
    _key, token = create_key

    assert authenticate(token: token, origin: "https://anywhere.example").success?
    assert authenticate(token: token, origin: nil, remote_ip: "198.51.100.4").success?
  end

  test "an origins-locked key authenticates from a matching Origin header" do
    _key, token = create_key(allowed_origins: "example.com, *.example.com")

    assert authenticate(token: token, origin: "https://example.com").success?
    assert authenticate(token: token, origin: "https://shop.example.com:8443").success?
  end

  test "an origins-locked key falls back to the Referer header" do
    _key, token = create_key(allowed_origins: "example.com")

    result = authenticate(token: token, referer: "https://example.com/widgets/1")

    assert result.success?
  end

  test "an origins-locked key refuses a request from another origin" do
    _key, token = create_key(allowed_origins: "example.com")

    result = authenticate(token: token, origin: "https://freeloader.example")

    refute result.success?
    assert_equal :origin_not_allowed, result.error_code
  end

  test "an origins-locked key refuses a request with no readable origin" do
    _key, token = create_key(allowed_origins: "example.com")

    result = authenticate(token: token)

    refute result.success?, "fail closed: no Origin and no Referer means no proof of origin"
    assert_equal :origin_not_allowed, result.error_code
  end

  test "an origins-locked key refuses a garbage Origin header without raising" do
    _key, token = create_key(allowed_origins: "example.com")

    ["null", "%%%", "http://[not a uri]", ""].each do |garbage|
      result = authenticate(token: token, origin: garbage)

      refute result.success?, "expected #{garbage.inspect} to be refused"
      assert_equal :origin_not_allowed, result.error_code
    end
  end

  test "a wildcard origin restriction admits subdomains but not the apex" do
    _key, token = create_key(allowed_origins: "*.example.com")

    assert authenticate(token: token, origin: "https://a.b.example.com").success?
    assert_equal :origin_not_allowed, authenticate(token: token, origin: "https://example.com").error_code
  end

  # =============================================================================
  # Authenticator: IPs
  # =============================================================================

  test "an IP-locked key authenticates from inside the configured range" do
    _key, token = create_key(allowed_ips: "10.0.0.0/8, 203.0.113.7")

    assert authenticate(token: token, remote_ip: "10.1.2.3").success?
    assert authenticate(token: token, remote_ip: "203.0.113.7").success?
  end

  test "an IP-locked key refuses an address outside the configured range" do
    _key, token = create_key(allowed_ips: "10.0.0.0/8")

    result = authenticate(token: token, remote_ip: "192.0.2.10")

    refute result.success?
    assert_equal :ip_not_allowed, result.error_code
  end

  test "an IP-locked key refuses an unreadable client address" do
    _key, token = create_key(allowed_ips: "10.0.0.0/8")

    assert_equal :ip_not_allowed, authenticate(token: token, remote_ip: nil).error_code
    assert_equal :ip_not_allowed, authenticate(token: token, remote_ip: "not-an-ip").error_code
  end

  test "the configured client_ip_resolver is what decides the address" do
    _key, token = create_key(allowed_ips: "198.51.100.0/24")
    ApiKeys.configure do |config|
      config.client_ip_resolver = ->(request) { request.headers["CF-Connecting-IP"] }
    end

    allowed = authenticate(token: token, remote_ip: "10.0.0.1", headers: { "CF-Connecting-IP" => "198.51.100.9" })
    refused = authenticate(token: token, remote_ip: "198.51.100.9", headers: { "CF-Connecting-IP" => "10.0.0.1" })

    assert allowed.success?, "the resolver's answer must win over remote_ip"
    assert_equal :ip_not_allowed, refused.error_code
  end

  test "a client_ip_resolver that blows up fails closed" do
    _key, token = create_key(allowed_ips: "10.0.0.0/8")
    ApiKeys.configure do |config|
      config.client_ip_resolver = ->(_request) { raise "resolver exploded" }
    end

    assert_equal :ip_not_allowed, authenticate(token: token, remote_ip: "10.1.2.3").error_code
  end

  # =============================================================================
  # Authenticator: combinations and coverage of every key
  # =============================================================================

  test "a key locked on both kinds needs both to match" do
    _key, token = create_key(allowed_origins: "example.com", allowed_ips: "10.0.0.0/8")

    assert authenticate(token: token, origin: "https://example.com", remote_ip: "10.1.2.3").success?
    assert_equal :ip_not_allowed,
                 authenticate(token: token, origin: "https://example.com", remote_ip: "192.0.2.1").error_code
    assert_equal :origin_not_allowed,
                 authenticate(token: token, origin: "https://other.example", remote_ip: "10.1.2.3").error_code
  end

  test "restrictions are enforced on legacy untyped keys too" do
    _key, token = create_key(allowed_origins: "example.com")

    assert_nil ApiKeys::ApiKey.last.key_type
    assert_equal :origin_not_allowed, authenticate(token: token, origin: "https://elsewhere.example").error_code
  end

  test "restrictions are enforced on typed keys of every type" do
    configure_key_types!
    publishable = @user.create_api_key!(name: "Widget", key_type: :publishable, allowed_origins: "example.com")
    secret = @user.create_api_key!(name: "Server", key_type: :secret, allowed_ips: "10.0.0.0/8")

    assert_equal :origin_not_allowed, authenticate(token: publishable.token, origin: "https://nope.example").error_code
    assert_equal :ip_not_allowed, authenticate(token: secret.token, remote_ip: "192.0.2.1").error_code
  end

  test "restriction checks survive the token cache and always read the fresh row" do
    ApiKeys::Services::Authenticator.stubs(:rails_cache).returns(FakeCache.new)
    key, token = create_key(allowed_origins: "example.com")

    assert authenticate(token: token, origin: "https://example.com").success?

    key.update!(allowed_origins: "example.org")

    result = authenticate(token: token, origin: "https://example.com")

    refute result.success?, "a tightened allowlist must take effect on the very next request"
    assert_equal :origin_not_allowed, result.error_code
  end

  test "an environment mismatch is reported before a restriction failure" do
    configure_key_types!
    ApiKeys.configure do |config|
      config.strict_environment_isolation = true
      config.current_environment = -> { :live }
    end
    key = @user.create_api_key!(name: "Widget", key_type: :publishable, environment: :test,
                                allowed_origins: "example.com")

    result = authenticate(token: key.token, origin: "https://nope.example")

    assert_equal :environment_mismatch, result.error_code
  end

  # =============================================================================
  # Controller concern: status codes and messages
  # =============================================================================

  test "a refused origin answers 403, not 401" do
    _key, token = create_key(allowed_origins: "example.com")

    controller = render_authentication(token: token, origin: "https://nope.example")

    assert_equal :forbidden, controller.rendered[:status]
    assert_equal :origin_not_allowed, controller.rendered[:json][:error]
    assert_nil controller.send(:current_api_key)
  end

  test "a refused IP answers 403, not 401" do
    _key, token = create_key(allowed_ips: "10.0.0.0/8")

    controller = render_authentication(token: token, remote_ip: "192.0.2.1")

    assert_equal :forbidden, controller.rendered[:status]
    assert_equal :ip_not_allowed, controller.rendered[:json][:error]
  end

  test "an invalid token still answers 401" do
    controller = render_authentication(token: "ak_not_a_real_token")

    assert_equal :unauthorized, controller.rendered[:status]
    assert_equal :invalid_token, controller.rendered[:json][:error]
  end

  test "an allowed request renders nothing and exposes the key" do
    key, token = create_key(allowed_origins: "example.com")

    controller = render_authentication(token: token, origin: "https://example.com")

    assert_nil controller.rendered
    assert_equal key, controller.send(:current_api_key)
  end

  test "the refusal message never echoes the configured allowlist" do
    _key, token = create_key(allowed_origins: "secret-internal.example, *.hidden.example",
                             allowed_ips: "10.9.8.7")

    origin_message = render_authentication(token: token, origin: "https://nope.example").rendered[:json][:message]
    ip_message = render_authentication(token: token, origin: "https://secret-internal.example",
                                       remote_ip: "192.0.2.1").rendered[:json][:message]

    refute_includes origin_message, "secret-internal.example"
    refute_includes origin_message, "hidden.example"
    refute_includes ip_message, "10.9.8.7"
    assert_includes origin_message, "restricted to specific web origins"
    assert_includes ip_message, "restricted to specific IP addresses"
  end

  test "a host application can translate the refusal message" do
    _key, token = create_key(allowed_origins: "example.com")
    I18n.backend.store_translations(:en, api_keys: { errors: { origin_not_allowed: "Not from there, sorry" } })

    controller = render_authentication(token: token, origin: "https://nope.example")

    assert_equal "Not from there, sorry", controller.rendered[:json][:message]
  ensure
    I18n.backend.reload!
  end

  test "forbidden error codes are exactly the request-context refusals" do
    assert_equal %i[origin_not_allowed ip_not_allowed], ApiKeys::Authentication::FORBIDDEN_ERROR_CODES
  end

  # =============================================================================
  # Model surface
  # =============================================================================

  test "allowed_origins= normalizes the raw string a form submits" do
    key, _token = create_key
    key.allowed_origins = "https://Shop.example/, *.app.example\n shop.example"
    key.save!

    assert_equal ["shop.example", "*.app.example"], key.reload.allowed_origins
    assert key.restricted?
  end

  test "allowed_ips= normalizes the raw string a form submits" do
    key, _token = create_key
    key.allowed_ips = "203.0.113.7, 10.0.0.0/8"
    key.save!

    assert_equal ["203.0.113.7", "10.0.0.0/8"], key.reload.allowed_ips
  end

  test "clearing a list makes the key unrestricted again" do
    key, _token = create_key(allowed_origins: "example.com")
    key.update!(allowed_origins: "")

    assert_empty key.reload.allowed_origins
    refute key.restricted?
    assert_equal({}, key.restrictions.to_h)
  end

  test "each list is edited independently" do
    key, _token = create_key(allowed_origins: "example.com")
    key.update!(allowed_ips: "10.0.0.0/8")

    assert_equal ["example.com"], key.reload.allowed_origins
    assert_equal ["10.0.0.0/8"], key.allowed_ips
  end

  test "restrictions accepts a hash and a value object" do
    key, _token = create_key
    key.update!(restrictions: { origins: ["example.com"] })

    assert_equal ["example.com"], key.reload.allowed_origins

    key.update!(restrictions: ApiKeys::Restrictions.wrap("ips" => ["10.0.0.0/8"]))

    assert_equal({ "ips" => ["10.0.0.0/8"] }, key.reload.restrictions.to_h)
  end

  test "restricted and unrestricted scopes partition the table" do
    restricted, _token = create_key(allowed_origins: "example.com")
    unrestricted = ApiKeys::ApiKey.create!(owner: @user, name: "Open Key")

    assert_equal [restricted.id], ApiKeys::ApiKey.restricted.pluck(:id)
    assert_equal [unrestricted.id], ApiKeys::ApiKey.unrestricted.pluck(:id)
  end

  test "create_api_key! accepts raw origin and IP strings" do
    key = @user.create_api_key!(name: "Widget Key", allowed_origins: "example.com, *.example.com",
                                allowed_ips: "10.0.0.0/8")

    assert_equal ["example.com", "*.example.com"], key.allowed_origins
    assert_equal ["10.0.0.0/8"], key.allowed_ips
  end

  test "create_api_key! accepts a restrictions hash" do
    key = @user.create_api_key!(name: "Widget Key", restrictions: { origins: ["example.com"] })

    assert_equal ["example.com"], key.allowed_origins
  end

  test "create_api_key! leaves keys unrestricted when nothing is asked for" do
    key = @user.create_api_key!(name: "Plain Key")

    assert_equal({}, key.restrictions.to_h)
    refute key.restricted?
  end

  test "restrictions are not part of the immutable authentication identity" do
    refute_includes ApiKeys::ApiKey::IMMUTABLE_IDENTITY_ATTRIBUTES, "restrictions"
  end

  test "a non-revocable public key can still have its restrictions tightened" do
    configure_key_types!
    key = @user.create_api_key!(name: "Widget", key_type: :publishable, allowed_origins: "example.com")

    refute key.revocable?
    assert key.update(allowed_origins: "example.com, *.example.com"),
           "restriction edits are the control a non-revocable key has: #{key.errors.full_messages}"
    assert_equal ["example.com", "*.example.com"], key.reload.allowed_origins
  end

  # =============================================================================
  # Validations
  # =============================================================================

  test "unknown restriction kinds are rejected" do
    key = ApiKeys::ApiKey.new(owner: @user, name: "Bad Key", restrictions: { "countries" => ["ES"] })

    refute key.valid?
    assert_includes key.errors.full_messages.join(" "), "unknown restriction kinds: countries"
  end

  test "a restrictions value that is not an object is rejected" do
    key = ApiKeys::ApiKey.new(owner: @user, name: "Bad Key")
    key.restrictions = "example.com"

    refute key.valid?
    assert_includes key.errors.full_messages.join(" "), "must be an object"
  end

  test "more than 100 entries in a list are rejected" do
    key = ApiKeys::ApiKey.new(owner: @user, name: "Bad Key",
                              restrictions: { "origins" => Array.new(101) { |index| "host#{index}.example.com" } })

    refute key.valid?
    assert_includes key.errors.full_messages.join(" "), "cannot contain more than 100 entries"
  end

  test "exactly 100 entries in a list are accepted" do
    key = ApiKeys::ApiKey.new(owner: @user, name: "Big Key",
                              restrictions: { "origins" => Array.new(100) { |index| "host#{index}.example.com" } })

    assert key.valid?, key.errors.full_messages.join(", ")
  end

  test "oversize entries are rejected" do
    key = ApiKeys::ApiKey.new(owner: @user, name: "Bad Key",
                              restrictions: { "origins" => ["#{'a' * 256}.example.com"] })

    refute key.valid?
    assert_includes key.errors.full_messages.join(" "), "cannot exceed 255 bytes"
  end

  test "malformed origin entries are rejected" do
    ["*", "*.", "exam ple.com", "example.com/path", "@example.com"].each do |entry|
      key = ApiKeys::ApiKey.new(owner: @user, name: "Bad Key", restrictions: { "origins" => [entry] })

      refute key.valid?, "expected #{entry.inspect} to be rejected"
      assert_includes key.errors.full_messages.join(" "), "must be bare hosts"
    end
  end

  test "malformed IP entries are rejected" do
    ["10.0.0.0/99", "999.0.0.1", "example.com", "10.0.0.1-10.0.0.9"].each do |entry|
      key = ApiKeys::ApiKey.new(owner: @user, name: "Bad Key", restrictions: { "ips" => [entry] })

      refute key.valid?, "expected #{entry.inspect} to be rejected"
      assert_includes key.errors.full_messages.join(" "), "valid IPv4/IPv6 addresses or CIDR ranges"
    end
  end

  test "valid origin and IP entries pass validation" do
    key = ApiKeys::ApiKey.new(owner: @user, name: "Good Key",
                              restrictions: { "origins" => ["example.com", "*.example.com", "localhost"],
                                              "ips" => ["203.0.113.7", "10.0.0.0/8", "2001:db8::/32"] })

    assert key.valid?, key.errors.full_messages.join(", ")
  end

  # =============================================================================
  # Key type ceilings
  # =============================================================================

  test "a key type may declare which restriction kinds its keys can carry" do
    configure_key_types!
    key = @user.api_keys.build(key_type: "publishable", environment: "test", name: "Widget",
                               restrictions: { "ips" => ["10.0.0.0/8"] })

    refute key.valid?
    assert_includes key.errors.full_messages.join(" "), "ips are not allowed for publishable keys"
  end

  test "a key type ceiling allows the kinds it lists" do
    configure_key_types!
    key = @user.api_keys.build(key_type: "publishable", environment: "test", name: "Widget",
                               restrictions: { "origins" => ["example.com"] })

    assert key.valid?, key.errors.full_messages.join(", ")
  end

  test "an omitted restrictions ceiling allows every kind" do
    ApiKeys.configure do |config|
      config.key_types = { standard: { prefix: "std", permissions: :all } }
      config.environments = { test: { prefix_segment: "test" } }
      config.current_environment = -> { :test }
    end
    key = @user.api_keys.build(key_type: "standard", environment: "test", name: "Anything",
                               restrictions: { "origins" => ["example.com"], "ips" => ["10.0.0.0/8"] })

    assert key.valid?, key.errors.full_messages.join(", ")
  end

  test "an empty restrictions ceiling forbids every kind" do
    ApiKeys.configure do |config|
      config.key_types = { locked: { prefix: "lk", permissions: :all, restrictions: [] } }
      config.environments = { test: { prefix_segment: "test" } }
      config.current_environment = -> { :test }
    end
    key = @user.api_keys.build(key_type: "locked", environment: "test", name: "No Restrictions",
                               restrictions: { "origins" => ["example.com"] })

    refute key.valid?
    assert_includes key.errors.full_messages.join(" "), "origins are not allowed for locked keys"
  end

  test "untyped keys are not subject to any ceiling" do
    key = ApiKeys::ApiKey.new(owner: @user, name: "Legacy Key",
                              restrictions: { "origins" => ["example.com"], "ips" => ["10.0.0.0/8"] })

    assert key.valid?, key.errors.full_messages.join(", ")
  end

  # =============================================================================
  # Configuration
  # =============================================================================

  test "client_ip_resolver defaults to the request's remote_ip" do
    request = FakeRequest.new(remote_ip: "198.51.100.22")

    assert_equal "198.51.100.22", ApiKeys.configuration.client_ip_resolver.call(request)
  end

  test "client_ip_resolver must be callable" do
    assert_raises(ArgumentError) { ApiKeys.configuration.client_ip_resolver = "remote_ip" }
    assert_raises(ArgumentError) { ApiKeys.configuration.client_ip_resolver = nil }
  end

  test "key type restriction ceilings are validated at assignment" do
    assert_raises(ArgumentError) do
      ApiKeys.configure do |config|
        config.key_types = { publishable: { prefix: "pk", permissions: %w[read], restrictions: [:countries] } }
      end
    end

    assert_raises(ArgumentError) do
      ApiKeys.configure do |config|
        config.key_types = { publishable: { prefix: "pk", permissions: %w[read], restrictions: :origins } }
      end
    end
  end

  test "key type restriction ceilings accept strings and symbols" do
    assert_nothing_raised do
      ApiKeys.configure do |config|
        config.key_types = {
          publishable: { prefix: "pk", permissions: %w[read], restrictions: ["origins"] },
          secret: { prefix: "sk", permissions: :all, restrictions: [:ips] }
        }
      end
    end
  end

  # =============================================================================
  # Missing column guard
  # =============================================================================

  test "the restrictions column is detected" do
    assert ApiKeys::ApiKey.restrictions_column?
  end

  test "writing restrictions without the column raises and names the generator" do
    ApiKeys::ApiKey.stubs(:restrictions_column?).returns(false)

    error = assert_raises(ApiKeys::Errors::RestrictionsMigrationRequiredError) do
      ApiKeys::ApiKey.new(owner: @user, name: "Key").restrictions = { "origins" => ["example.com"] }
    end

    assert_includes error.message, "rails generate api_keys:add_restrictions"
  end

  test "create_api_key! with restrictions raises without the column" do
    ApiKeys::ApiKey.stubs(:restrictions_column?).returns(false)

    assert_raises(ApiKeys::Errors::RestrictionsMigrationRequiredError) do
      @user.create_api_key!(name: "Widget Key", allowed_origins: "example.com")
    end
  end

  test "configuring a key type ceiling raises without the column" do
    configure_key_types!
    ApiKeys::ApiKey.stubs(:restrictions_column?).returns(false)

    assert_raises(ApiKeys::Errors::RestrictionsMigrationRequiredError) do
      @user.create_api_key!(name: "Widget", key_type: :publishable)
    end
  end

  test "keys without the column behave as unrestricted" do
    key, _token = create_key
    ApiKeys::ApiKey.stubs(:restrictions_column?).returns(false)

    assert key.restrictions.unrestricted?
    refute key.restricted?
    assert_empty key.allowed_origins
    assert key.valid?, key.errors.full_messages.join(", ")
  end

  private

  def configure_key_types!
    ApiKeys.configure do |config|
      config.key_types = {
        publishable: {
          prefix: "pk",
          permissions: %w[read],
          revocable: false,
          public: true,
          restrictions: [:origins]
        },
        secret: {
          prefix: "sk",
          permissions: :all,
          restrictions: [:ips]
        }
      }
      config.environments = { test: { prefix_segment: "test" }, live: { prefix_segment: "live" } }
      config.current_environment = -> { :test }
    end
  end
end
