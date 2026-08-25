# frozen_string_literal: true

require "ipaddr"
require "uri"
require_relative "logging"

module ApiKeys
  # Value object describing *where* an API key may be used from: a list of web
  # origins (hosts, with optional `*.` subdomain wildcards) and a list of IP
  # addresses or CIDR ranges.
  #
  # Restrictions are plain data stored in the `restrictions` JSON column:
  #
  #   { "origins" => ["example.com", "*.example.com"],
  #     "ips"     => ["203.0.113.7", "10.0.0.0/8", "2001:db8::/32"] }
  #
  # Matching semantics (normative):
  #
  # - Within a list: OR. Any entry that matches admits the request.
  # - Across lists: AND. Every list that is present and non-empty must pass.
  # - Empty (or absent) restrictions mean unrestricted. Presence is the toggle.
  # - Every failure mode fails closed: a locked list plus an unreadable request
  #   context refuses the request.
  #
  # The object is immutable, has no Active Record dependency, and never raises
  # on malformed input: `wrap` coerces whatever it is given, and the model's
  # validations are what reject nonsense before it reaches the database.
  class Restrictions
    include ApiKeys::Logging

    # The restriction kinds this gem understands. Anything else stored in the
    # column is a validation error rather than a silently ignored key.
    KINDS = %i[origins ips].freeze
    KIND_NAMES = KINDS.map(&:to_s).freeze

    # Entries are split on commas, whitespace, and newlines so that a single
    # text field can hold a whole list ("example.com, *.example.com").
    ENTRY_SEPARATOR = /[\s,;]+/

    # A bare host, optionally prefixed with a `*.` subdomain wildcard.
    # `*` alone is deliberately invalid: an empty list already means "anywhere".
    ORIGIN_ENTRY_PATTERN = /\A(?:\*\.)?[a-z0-9_-]+(?:\.[a-z0-9_-]+)*\z/

    attr_reader :origins, :ips

    class << self
      # Coerces anything into a Restrictions instance. Never raises.
      #
      # @param value [Restrictions, Hash, nil, Object] The stored column value,
      #   a hash of lists, or an existing instance.
      # @return [ApiKeys::Restrictions]
      def wrap(value)
        return value if value.is_a?(self)
        return none if value.nil?
        return new(origins: [], ips: [], extras: {}) unless value.is_a?(Hash)

        known, extras = value.partition { |key, _entries| KIND_NAMES.include?(key.to_s) }
        known = known.to_h { |key, entries| [key.to_s, entries] }

        new(
          origins: coerce_list(known["origins"]),
          ips: coerce_list(known["ips"]),
          extras: extras.to_h
        )
      end

      # The shared empty instance: no origins, no IPs, no restrictions at all.
      # @return [ApiKeys::Restrictions]
      def none
        @none ||= new(origins: [], ips: [], extras: {}).freeze
      end

      # Forgiving parser for the raw string a dashboard text field submits.
      # Accepts full URLs, bare hosts, commas, newlines, and stray whitespace;
      # returns bare lowercase hosts, de-duplicated, order preserved.
      #
      #   normalize_origins("https://Shop.example/, *.app.example\n x")
      #   # => ["shop.example", "*.app.example", "x"]
      #
      # @param value [String, Array, nil] Raw user input.
      # @return [Array<String>] Normalized origin entries.
      def normalize_origins(value)
        tokenize(value).filter_map { |token| origin_host(token) }.uniq
      end

      # Forgiving parser for IP/CIDR input. Entries that stdlib IPAddr cannot
      # parse at all are dropped; everything else is kept verbatim (lowercased)
      # so validation, not the parser, is what reports a malformed range.
      #
      # @param value [String, Array, nil] Raw user input.
      # @return [Array<String>] Normalized IP entries.
      def normalize_ips(value)
        tokenize(value).map(&:downcase).uniq
      end

      # Extracts the host the browser claims the request came from: the Origin
      # header when present, the Referer header otherwise. Returns nil when
      # neither is present or parseable, which callers must treat as a refusal.
      #
      # @param request [ActionDispatch::Request, #headers, nil]
      # @return [String, nil] Bare lowercase host.
      def extract_origin_host(request)
        headers = request.headers if request.respond_to?(:headers)
        return nil unless headers.respond_to?(:[])

        %w[Origin Referer].each do |header_name|
          host = host_from_url(headers[header_name])
          return host if host
        end

        nil
      rescue StandardError
        # A hostile or exotic request object must never take an endpoint down;
        # an unreadable origin is simply an origin that matches nothing.
        nil
      end

      # Splits raw input into candidate entries without interpreting them.
      # @api private
      def tokenize(value)
        entries = case value
                  when nil then []
                  when String then value.split(ENTRY_SEPARATOR)
                  when Array then value.flat_map { |entry| entry.is_a?(String) ? entry.split(ENTRY_SEPARATOR) : [entry] }
                  else [value]
                  end

        entries.filter_map do |entry|
          next unless entry.is_a?(String)

          trimmed = entry.strip
          trimmed unless trimmed.empty?
        end
      end

      # Reduces a single user-supplied entry to a bare lowercase host.
      # Full URLs give up their host; bare hosts keep everything before the
      # first slash, colon, or question mark. Returns nil when nothing is left.
      # @api private
      def origin_host(entry)
        candidate = entry.to_s.strip
        return nil if candidate.empty?

        if candidate.include?("//")
          host = host_from_url(candidate)
          return host
        end

        host = candidate.split(%r{[/?#]}).first.to_s
        host = host.sub(/:\d*\z/, "") # Strip a trailing port ("example.com:3000").
        host = host.delete_prefix("[").delete_suffix("]") # IPv6 literals.
        host = host.downcase
        host.empty? ? nil : host
      end

      # Pulls the host out of a full URL, tolerating garbage.
      # @api private
      def host_from_url(value)
        return nil unless value.is_a?(String)

        trimmed = value.strip
        return nil if trimmed.empty?

        host = URI.parse(trimmed).host
        return nil if host.nil? || host.empty?

        host.delete_prefix("[").delete_suffix("]").downcase
      rescue URI::Error, ArgumentError
        nil
      end

      # Coerces one stored list into an array of entries, preserving anything
      # that is not a string so validations can report it instead of the value
      # disappearing silently.
      # @api private
      def coerce_list(value)
        entries = case value
                  when nil then []
                  when String then value.split(ENTRY_SEPARATOR)
                  when Array then value
                  else [value]
                  end

        entries.filter_map do |entry|
          next entry unless entry.is_a?(String)

          trimmed = entry.strip.downcase
          trimmed unless trimmed.empty?
        end
      end

      # Whether a stored origin entry is shaped like a host or `*.host`.
      # @api private
      def valid_origin_entry?(entry)
        entry.is_a?(String) && entry.match?(ORIGIN_ENTRY_PATTERN)
      end

      # Whether a stored IP entry is a single address or a CIDR range.
      # @api private
      def valid_ip_entry?(entry)
        parse_ip(entry) ? true : false
      end

      # Parses an address or range with stdlib IPAddr. A bare address is a /32
      # (or /128), so `IPAddr#include?` answers exact matches and range matches
      # through a single code path.
      # @api private
      def parse_ip(value)
        return nil unless value.is_a?(String)

        trimmed = value.strip
        return nil if trimmed.empty?

        address = IPAddr.new(trimmed)
        address.ipv6? && address.ipv4_mapped? ? address.native : address
      rescue IPAddr::Error, ArgumentError
        nil
      end
    end

    # @param origins [Array<String>] Already-coerced origin entries.
    # @param ips [Array<String>] Already-coerced IP entries.
    # @param extras [Hash] Unrecognized keys, preserved so validation sees them.
    def initialize(origins: [], ips: [], extras: {})
      @origins = origins.freeze
      @ips = ips.freeze
      @extras = extras.freeze
      freeze
    end

    # Unrecognized keys found in the stored hash. Their presence is a
    # validation error; they are kept so the error can name them.
    # @return [Hash]
    attr_reader :extras

    # @return [Boolean] true when this key may be used from anywhere.
    def unrestricted?
      origins.empty? && ips.empty?
    end

    # @return [Boolean] true when at least one list is locked.
    def restricted?
      !unrestricted?
    end

    # @return [Array<Symbol>] The restriction kinds actually in use.
    def kinds
      KINDS.select { |kind| public_send(kind).any? }
    end

    # The storage shape: known lists that have entries, plus any unrecognized
    # keys exactly as they were found.
    # @return [Hash]
    def to_h
      hash = {}
      hash["origins"] = origins.dup if origins.any?
      hash["ips"] = ips.dup if ips.any?
      hash.merge(extras)
    end

    alias as_json to_h

    # Does this request context satisfy every locked list?
    #
    # @param origin_host [String, nil] Host from Origin/Referer.
    # @param ip [String, nil] Client IP address.
    # @return [Boolean]
    def allows?(origin_host: nil, ip: nil)
      origin_allowed?(origin_host) && ip_allowed?(ip)
    end

    # @param host [String, nil] Bare host to check.
    # @return [Boolean] true when the origins list is empty or one entry matches.
    #   A locked list plus a nil/blank host refuses: fail closed.
    def origin_allowed?(host)
      return true if origins.empty?

      candidate = host.to_s.strip.downcase
      return false if candidate.empty?

      origins.any? { |entry| origin_entry_matches?(entry, candidate) }
    end

    # @param ip [String, nil] Client IP address.
    # @return [Boolean] true when the IP list is empty or one entry contains it.
    #   A locked list plus an unparseable address refuses: fail closed.
    def ip_allowed?(ip)
      return true if ips.empty?

      address = self.class.parse_ip(ip.is_a?(String) ? ip : ip.to_s)
      return false unless address

      ips.any? { |entry| ip_entry_matches?(entry, address) }
    end

    def ==(other)
      other.is_a?(self.class) && other.to_h == to_h
    end
    alias eql? ==

    def hash
      to_h.hash
    end

    def inspect
      "#<#{self.class.name} origins=#{origins.inspect} ips=#{ips.inspect}>"
    end

    private

    # ApiKeys::Logging memoizes its logger in an instance variable, and this
    # value object is frozen. Resolve the logger fresh instead.
    def logger
      defined?(Rails) ? Rails.logger : nil
    end

    # `*.example.com` matches any subdomain at any depth, but never the apex —
    # Google's rule. List the apex separately when you want both.
    def origin_entry_matches?(entry, host)
      return false unless entry.is_a?(String)

      if entry.start_with?("*.")
        suffix = entry.delete_prefix("*")
        host.end_with?(suffix) && host.length > suffix.length
      else
        entry == host
      end
    end

    # A stored entry that no longer parses matches nothing and says so once.
    # Validation keeps these out; this covers rows written around validations.
    def ip_entry_matches?(entry, address)
      range = self.class.parse_ip(entry)
      unless range
        log_warn "[ApiKeys Security] Ignored an unparseable stored IP restriction entry."
        return false
      end

      range.include?(address)
    end
  end
end
