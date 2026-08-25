# frozen_string_literal: true

require "test_helper"

# Unit matrix for the ApiKeys::Restrictions value object: parsing, normalizing,
# and the matching semantics the authenticator relies on.
class RestrictionsTest < ApiKeys::Test
  # A minimal stand-in for ActionDispatch::Request: all the value object needs
  # is something that answers #headers.
  class FakeRequest
    attr_reader :headers

    def initialize(headers = {})
      @headers = headers
    end
  end

  # Records every warning the value object emits.
  class RecordingLogger
    attr_reader :warnings

    def initialize
      @warnings = []
    end

    def warn(message)
      @warnings << message
    end

    def debug(_message); end
    def error(_message); end
  end

  def restrictions(origins: [], ips: [])
    ApiKeys::Restrictions.wrap("origins" => origins, "ips" => ips)
  end

  # =============================================================================
  # Origin matching
  # =============================================================================

  test "an exact host matches itself" do
    locked = restrictions(origins: ["example.com"])

    assert locked.origin_allowed?("example.com")
    refute locked.origin_allowed?("other.com")
  end

  test "host matching is case-insensitive on both sides" do
    locked = restrictions(origins: ["Example.COM"])

    assert locked.origin_allowed?("EXAMPLE.com")
    assert locked.origin_allowed?("example.com")
  end

  test "host matching is port-blind and scheme-blind" do
    locked = restrictions(origins: ["x.example"])
    request = FakeRequest.new("Origin" => "https://x.example:8443")

    assert locked.origin_allowed?(ApiKeys::Restrictions.extract_origin_host(request))
    assert locked.origin_allowed?(ApiKeys::Restrictions.extract_origin_host(FakeRequest.new("Origin" => "http://x.example")))
  end

  test "a subdomain wildcard matches subdomains at any depth" do
    locked = restrictions(origins: ["*.example.com"])

    assert locked.origin_allowed?("a.example.com")
    assert locked.origin_allowed?("a.b.example.com")
  end

  test "a subdomain wildcard does not match the apex domain" do
    locked = restrictions(origins: ["*.example.com"])

    refute locked.origin_allowed?("example.com")
  end

  test "a subdomain wildcard does not match a lookalike suffix" do
    locked = restrictions(origins: ["*.example.com"])

    refute locked.origin_allowed?("evilexample.com")
    refute locked.origin_allowed?("example.com.evil.com")
  end

  test "listing the apex alongside the wildcard covers both" do
    locked = restrictions(origins: ["example.com", "*.example.com"])

    assert locked.origin_allowed?("example.com")
    assert locked.origin_allowed?("shop.example.com")
    refute locked.origin_allowed?("example.org")
  end

  test "a bare asterisk is not a valid origin entry" do
    refute ApiKeys::Restrictions.valid_origin_entry?("*")
    refute ApiKeys::Restrictions.valid_origin_entry?("*.")
    refute ApiKeys::Restrictions.valid_origin_entry?("exam ple.com")
    refute ApiKeys::Restrictions.valid_origin_entry?("example.com/path")
    assert ApiKeys::Restrictions.valid_origin_entry?("example.com")
    assert ApiKeys::Restrictions.valid_origin_entry?("*.example.com")
    assert ApiKeys::Restrictions.valid_origin_entry?("localhost")
    assert ApiKeys::Restrictions.valid_origin_entry?("2001:db8::1")
    refute ApiKeys::Restrictions.valid_origin_entry?("#{'a' * 64}.example.com")
    refute ApiKeys::Restrictions.valid_origin_entry?("#{'a' * 250}.com")
  end

  test "a locked origin list refuses a nil or blank host" do
    locked = restrictions(origins: ["example.com"])

    refute locked.origin_allowed?(nil)
    refute locked.origin_allowed?("")
    refute locked.origin_allowed?("   ")
  end

  test "an empty origin list allows every host" do
    assert ApiKeys::Restrictions.none.origin_allowed?("anything.com")
    assert ApiKeys::Restrictions.none.origin_allowed?(nil)
  end

  # =============================================================================
  # normalize_origins: the forgiving parser dashboards submit into
  # =============================================================================

  test "normalize_origins accepts full URLs, wildcards, commas, and newlines" do
    assert_equal ["shop.example", "*.app.example", "x"],
                 ApiKeys::Restrictions.normalize_origins("https://Shop.example/, *.app.example\n x")
  end

  test "normalize_origins strips trailing slashes, paths, and ports" do
    assert_equal ["example.com"], ApiKeys::Restrictions.normalize_origins("example.com/")
    assert_equal ["example.com"], ApiKeys::Restrictions.normalize_origins("example.com:3000")
    assert_equal ["example.com"], ApiKeys::Restrictions.normalize_origins("https://example.com/some/path?q=1")
  end

  test "normalize_origins de-duplicates entries that normalize to the same host" do
    assert_equal ["example.com"], ApiKeys::Restrictions.normalize_origins("Example.com, https://example.com/, example.com")
  end

  test "normalize_origins preserves invalid nonblank entries for validation" do
    assert_equal ["https://", "example.com"], ApiKeys::Restrictions.normalize_origins("https://, example.com,   ")
    assert_empty ApiKeys::Restrictions.normalize_origins(nil)
    assert_empty ApiKeys::Restrictions.normalize_origins("")
  end

  test "normalize_origins accepts arrays as well as raw strings" do
    assert_equal ["a.com", "b.com"], ApiKeys::Restrictions.normalize_origins(["A.com", "https://b.com"])
    assert_equal ["a.com", 42], ApiKeys::Restrictions.normalize_origins(["A.com", "  ", 42])
  end

  test "origin normalization handles IP literals and empty host fragments" do
    assert_equal "2001:db8::1", ApiKeys::Restrictions.origin_host("[2001:db8::1]:8443")
    assert_equal "2001:db8::1", ApiKeys::Restrictions.origin_host("2001:DB8::1")
    assert_nil ApiKeys::Restrictions.origin_host("")
    assert_nil ApiKeys::Restrictions.origin_host("/")
    assert_nil ApiKeys::Restrictions.host_from_url(42)
    assert_nil ApiKeys::Restrictions.host_from_url("  ")
    assert_nil ApiKeys::Restrictions.host_from_url("relative/path")
  end

  test "normalize_origins keeps invalid entries for validation to report" do
    # Dropping "*" here would silently leave the key unrestricted; validation
    # is what tells the user their entry is wrong.
    assert_equal ["*"], ApiKeys::Restrictions.normalize_origins("*")
  end

  # =============================================================================
  # IP matching
  # =============================================================================

  test "an exact IPv4 address matches itself" do
    locked = restrictions(ips: ["203.0.113.7"])

    assert locked.ip_allowed?("203.0.113.7")
    refute locked.ip_allowed?("203.0.113.8")
  end

  test "a bare IPv4 address is a /32 and matches nothing else" do
    assert_equal 32, ApiKeys::Restrictions.parse_ip("203.0.113.7").prefix
    refute restrictions(ips: ["203.0.113.7"]).ip_allowed?("203.0.113.6")
  end

  test "an IPv4 CIDR range matches inside its boundaries and refuses outside" do
    locked = restrictions(ips: ["10.0.0.0/24"])

    assert locked.ip_allowed?("10.0.0.0")
    assert locked.ip_allowed?("10.0.0.255")
    refute locked.ip_allowed?("10.0.1.0")
    refute locked.ip_allowed?("9.255.255.255")
  end

  test "an exact IPv6 address matches itself" do
    locked = restrictions(ips: ["2001:db8::1"])

    assert locked.ip_allowed?("2001:db8::1")
    refute locked.ip_allowed?("2001:db8::2")
  end

  test "an IPv6 CIDR range matches addresses inside it" do
    locked = restrictions(ips: ["2001:db8::/32"])

    assert locked.ip_allowed?("2001:db8::1")
    assert locked.ip_allowed?("2001:db8:ffff::abcd")
    refute locked.ip_allowed?("2001:db9::1")
  end

  test "address families never match across each other" do
    refute restrictions(ips: ["10.0.0.0/8"]).ip_allowed?("2001:db8::1")
    refute restrictions(ips: ["2001:db8::/32"]).ip_allowed?("10.0.0.1")
  end

  test "an IPv4-mapped IPv6 address is matched as its IPv4 form" do
    assert restrictions(ips: ["203.0.113.0/24"]).ip_allowed?("::ffff:203.0.113.7")
  end

  test "a locked IP list refuses a nil or unparseable address" do
    locked = restrictions(ips: ["10.0.0.0/8"])

    refute locked.ip_allowed?(nil)
    refute locked.ip_allowed?("")
    refute locked.ip_allowed?("not-an-ip")
    refute locked.ip_allowed?("10.0.0.1, 10.0.0.2")
  end

  test "an empty IP list allows every address" do
    assert ApiKeys::Restrictions.none.ip_allowed?("10.0.0.1")
    assert ApiKeys::Restrictions.none.ip_allowed?(nil)
  end

  test "an unparseable stored IP entry makes the whole policy fail closed" do
    locked = restrictions(ips: ["10.0.0.0/8", "not-an-ip"])

    assert locked.malformed?
    refute locked.ip_allowed?("10.1.2.3"), "a valid sibling must not hide policy corruption"
    refute locked.ip_allowed?("192.0.2.1")
  end

  test "normalize_ips splits, downcases, and de-duplicates" do
    assert_equal ["203.0.113.7", "10.0.0.0/8"], ApiKeys::Restrictions.normalize_ips("203.0.113.7, 10.0.0.0/8")
    assert_equal ["2001:db8::/32"], ApiKeys::Restrictions.normalize_ips("2001:DB8::/32\n2001:db8::/32")
    assert_empty ApiKeys::Restrictions.normalize_ips(nil)
  end

  test "valid_ip_entry? accepts addresses and ranges and refuses nonsense" do
    assert ApiKeys::Restrictions.valid_ip_entry?("203.0.113.7")
    assert ApiKeys::Restrictions.valid_ip_entry?("10.0.0.0/8")
    assert ApiKeys::Restrictions.valid_ip_entry?("2001:db8::/32")
    refute ApiKeys::Restrictions.valid_ip_entry?("10.0.0.0/99")
    refute ApiKeys::Restrictions.valid_ip_entry?("999.0.0.1")
    refute ApiKeys::Restrictions.valid_ip_entry?("example.com")
    refute ApiKeys::Restrictions.valid_ip_entry?(42)
  end

  # =============================================================================
  # Combination semantics: OR within a list, AND across lists
  # =============================================================================

  test "within a list any entry admits the request" do
    locked = restrictions(origins: ["a.com", "b.com"])

    assert locked.allows?(origin_host: "a.com")
    assert locked.allows?(origin_host: "b.com")
    refute locked.allows?(origin_host: "c.com")
  end

  test "across lists every locked list must pass" do
    locked = restrictions(origins: ["a.com"], ips: ["10.0.0.0/8"])

    assert locked.allows?(origin_host: "a.com", ip: "10.1.2.3")
    refute locked.allows?(origin_host: "a.com", ip: "192.0.2.1"), "the IP list must still be enforced"
    refute locked.allows?(origin_host: "b.com", ip: "10.1.2.3"), "the origin list must still be enforced"
    refute locked.allows?(origin_host: nil, ip: "10.1.2.3"), "an origin-locked key is unusable without an origin"
  end

  test "an unrestricted key allows any context at all" do
    assert ApiKeys::Restrictions.none.allows?(origin_host: nil, ip: nil)
  end

  # =============================================================================
  # wrap, to_h, and general shape
  # =============================================================================

  test "unrestricted? is true only when both lists are empty" do
    assert ApiKeys::Restrictions.none.unrestricted?
    assert ApiKeys::Restrictions.wrap({}).unrestricted?
    refute restrictions(origins: ["a.com"]).unrestricted?
    refute restrictions(ips: ["10.0.0.1"]).unrestricted?
    assert restrictions(origins: ["a.com"]).restricted?
  end

  test "kinds names only the lists actually in use" do
    assert_empty ApiKeys::Restrictions.none.kinds
    assert_equal [:origins], restrictions(origins: ["a.com"]).kinds
    assert_equal [:ips], restrictions(ips: ["10.0.0.1"]).kinds
    assert_equal [:origins, :ips], restrictions(origins: ["a.com"], ips: ["10.0.0.1"]).kinds
  end

  test "to_h drops empty lists" do
    assert_equal({}, ApiKeys::Restrictions.none.to_h)
    assert_equal({ "origins" => ["a.com"] }, restrictions(origins: ["a.com"]).to_h)
    assert_equal({ "ips" => ["10.0.0.1"] }, restrictions(ips: ["10.0.0.1"]).to_h)
  end

  test "wrap is nil-safe and idempotent" do
    assert ApiKeys::Restrictions.wrap(nil).unrestricted?

    wrapped = restrictions(origins: ["a.com"])
    assert_same wrapped, ApiKeys::Restrictions.wrap(wrapped)
    assert_equal wrapped, ApiKeys::Restrictions.wrap(wrapped.to_h)
  end

  test "wrap normalizes symbol keys, raw strings, and stray whitespace" do
    wrapped = ApiKeys::Restrictions.wrap(origins: " Example.com , *.example.com ", ips: ["10.0.0.0/8"])

    assert_equal ["example.com", "*.example.com"], wrapped.origins
    assert_equal ["10.0.0.0/8"], wrapped.ips
  end

  test "wrap never raises on values that are not hashes" do
    ["garbage", [1, 2, 3], 42].each do |value|
      wrapped = ApiKeys::Restrictions.wrap(value)
      assert wrapped.malformed?
      refute wrapped.unrestricted?
    end
  end

  test "wrap fails closed when a hostile hash raises during coercion" do
    hostile = Class.new(Hash) do
      def partition
        raise "hostile hash"
      end
    end.new

    wrapped = ApiKeys::Restrictions.wrap(hostile)

    assert wrapped.malformed?
    refute wrapped.unrestricted?
  end

  test "wrap keeps unknown keys so validation can name them" do
    wrapped = ApiKeys::Restrictions.wrap("origins" => ["a.com"], "countries" => ["ES"])

    assert_equal({ "origins" => ["a.com"], "countries" => ["ES"] }, wrapped.to_h)
    assert_equal({ "countries" => ["ES"] }, wrapped.extras)
  end

  test "wrap keeps non-string entries so validation can reject them" do
    wrapped = ApiKeys::Restrictions.wrap("origins" => [42])

    assert_equal [42], wrapped.origins
    refute wrapped.origin_allowed?("42"), "a non-string entry can never match a host"
  end

  test "wrap coerces a scalar list value into a single entry" do
    assert_equal [42], ApiKeys::Restrictions.wrap("origins" => 42).origins
    assert_equal [42], ApiKeys::Restrictions.normalize_origins(42)
    assert_equal [42], ApiKeys::Restrictions.normalize_ips(42)
  end

  test "equal restrictions hash alike, so they work as hash keys" do
    counts = Hash.new(0)
    counts[restrictions(origins: ["a.com"])] += 1
    counts[restrictions(origins: ["a.com"])] += 1
    counts[restrictions(origins: ["b.com"])] += 1

    assert_equal 2, counts.size
    assert_equal 2, counts[restrictions(origins: ["a.com"])]
  end

  test "equality and inspect never leak beyond the two lists" do
    assert_equal restrictions(origins: ["a.com"]), restrictions(origins: ["a.com"])
    refute_equal restrictions(origins: ["a.com"]), restrictions(origins: ["b.com"])
    refute_equal restrictions(origins: ["a.com"]), "a.com"
    assert_includes restrictions(origins: ["a.com"]).inspect, "a.com"
  end

  # =============================================================================
  # extract_origin_host
  # =============================================================================

  test "extract_origin_host reads the Origin header first" do
    request = FakeRequest.new("Origin" => "https://Shop.example.com", "Referer" => "https://other.com/page")

    assert_equal "shop.example.com", ApiKeys::Restrictions.extract_origin_host(request)
  end

  test "extract_origin_host falls back to the Referer header" do
    request = FakeRequest.new("Referer" => "https://shop.example.com/products/1?utm=x")

    assert_equal "shop.example.com", ApiKeys::Restrictions.extract_origin_host(request)
  end

  test "extract_origin_host ignores a port" do
    request = FakeRequest.new("Origin" => "https://x.example:8443")

    assert_equal "x.example", ApiKeys::Restrictions.extract_origin_host(request)
  end

  test "extract_origin_host returns nil when no header carries an origin" do
    assert_nil ApiKeys::Restrictions.extract_origin_host(FakeRequest.new)
    assert_nil ApiKeys::Restrictions.extract_origin_host(FakeRequest.new("Origin" => ""))
    assert_nil ApiKeys::Restrictions.extract_origin_host(nil)
  end

  test "extract_origin_host returns nil for unparseable or opaque origins" do
    assert_nil ApiKeys::Restrictions.extract_origin_host(FakeRequest.new("Origin" => "null"))
    assert_nil ApiKeys::Restrictions.extract_origin_host(FakeRequest.new("Origin" => "http://[not a uri]"))
    assert_nil ApiKeys::Restrictions.extract_origin_host(FakeRequest.new("Origin" => "%%%"))
    assert_nil ApiKeys::Restrictions.extract_origin_host(FakeRequest.new("Origin" => 42))
  end

  test "extract_origin_host survives a request object that cannot answer headers" do
    assert_nil ApiKeys::Restrictions.extract_origin_host(Object.new)
    assert_nil ApiKeys::Restrictions.extract_origin_host(FakeRequest.new(Object.new))
  end

  test "extract_origin_host survives headers that raise when read" do
    exploding_headers = Object.new
    def exploding_headers.[](_name)
      raise IOError, "headers unavailable"
    end

    assert_nil ApiKeys::Restrictions.extract_origin_host(FakeRequest.new(exploding_headers))
  end
end
