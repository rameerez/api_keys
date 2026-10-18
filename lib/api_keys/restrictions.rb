# frozen_string_literal: true

require "ipaddr"
require "uri"

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
  # The object is immutable and has no Active Record dependency. Malformed
  # persisted values are represented explicitly and deny authentication; model
  # validations keep them out during ordinary writes.
  class Restrictions
    # The restriction kinds this gem understands. Anything else stored in the
    # column is a validation error rather than a silently ignored key.
    KINDS = %i[origins ips].freeze
    KIND_NAMES = KINDS.map(&:to_s).freeze

    # Entries are split on commas, whitespace, and newlines so that a single
    # text field can hold a whole list ("example.com, *.example.com").
    ENTRY_SEPARATOR = /[\s,;]+/

    # A bare host, optionally prefixed with a `*.` subdomain wildcard.
    # `*` alone is deliberately invalid: an empty list already means "anywhere".
    DNS_LABEL = /[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?/
    ORIGIN_ENTRY_PATTERN = /\A(?:\*\.)?#{DNS_LABEL}(?:\.#{DNS_LABEL})*\z/

    attr_reader :origins, :ips, :extras

    class << self
      # Coerces anything into a Restrictions instance. Never raises.
      #
      # @param value [Restrictions, Hash, nil, Object] The stored column value,
      #   a hash of lists, or an existing instance.
      # @return [ApiKeys::Restrictions]
      def wrap(value)
        return value if value.is_a?(self)
        return none if value.nil?
        return new(origins: [], ips: [], extras: {}, malformed: true) unless value.is_a?(Hash)

        known, extras = value.partition { |key, _entries| KIND_NAMES.include?(key.to_s) }
        known = known.to_h { |key, entries| [key.to_s, entries] }

        # Only an absent kind means "no list". A kind that is present must
        # hold a list; `"ips" => nil` is as malformed as `"ips" => false`.
        new(
          origins: known.key?("origins") ? coerce_list(known["origins"]) : [],
          ips: known.key?("ips") ? coerce_list(known["ips"]) : [],
          extras: extras.to_h
        )
      rescue StandardError
        # Stored policy is untrusted input. Preserve the core invariant even if
        # an exotic object raises while being coerced: malformed never means
        # unrestricted.
        new(origins: [], ips: [], extras: {}, malformed: true)
      end

      # Reads a restrictions hash a caller passes in (`ApiKey#restrictions=`
      # and `create_api_key!(restrictions:)`). A kind given as `nil` or blank
      # text is cleared, exactly as the `allowed_origins=` / `allowed_ips=`
      # writers clear it. Everything else passes through untouched, so
      # `false`, wrong types, and malformed list members still fail
      # validation. Stored rows never go through here: `wrap` reads them
      # strictly, and a stored `null` refuses authentication.
      #
      # @param value [Hash, Object] Caller input; non-hashes are returned as is.
      # @return [Hash, Object]
      def normalize_input(value)
        return value unless value.is_a?(Hash)

        value.to_h do |kind, entries|
          cleared = KIND_NAMES.include?(kind.to_s) && blank_input?(entries)
          [kind, cleared ? [] : entries]
        end
      rescue StandardError
        value
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
      # Non-string entries are preserved so validation can report malformed
      # programmatic input instead of silently erasing a requested policy.
      # @param value [String, Array, nil] Raw user input.
      # @return [Array] Normalized origin entries.
      def normalize_origins(value)
        tokenize(value).map do |token|
          next token unless token.is_a?(String)

          origin_host(token) || token.strip.downcase
        end.uniq
      end

      # Forgiving parser for IP/CIDR input. String entries are kept verbatim
      # (lowercased) so validation, not the parser, reports malformed ranges.
      # Non-string entries are likewise preserved for validation.
      #
      # @param value [String, Array, nil] Raw user input.
      # @return [Array<String>] Normalized IP entries.
      def normalize_ips(value)
        tokenize(value).map { |entry| entry.is_a?(String) ? entry.downcase : entry }.uniq
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

        origin = headers["Origin"]
        unless origin.nil? || (origin.is_a?(String) && origin.strip.empty?)
          # Origin has precedence over Referer. A present-but-invalid Origin
          # (including the browser's opaque `null` origin) must not be rescued
          # by a friendlier Referer value.
          return host_from_url(origin)
        end

        host_from_url(headers["Referer"])
      rescue StandardError
        # A hostile or exotic request object must never take an endpoint down;
        # an unreadable origin is simply an origin that matches nothing.
        nil
      end

      # Splits raw input into candidate entries without interpreting them.
      #
      # `nil` and blank text are the raw-input spellings of an empty list (a
      # cleared dashboard field). Every other non-string value, including
      # `false` and a `nil` inside an array, is kept as an entry so that
      # validation rejects it: malformed input must never read as "unrestricted".
      # @api private
      def tokenize(value)
        entries = case value
                  when nil then []
                  when String then value.split(ENTRY_SEPARATOR)
                  when Array then value.flat_map { |entry| entry.is_a?(String) ? entry.split(ENTRY_SEPARATOR) : [entry] }
                  else [value]
                  end

        entries.each_with_object([]) do |entry, tokens|
          unless entry.is_a?(String)
            tokens << entry
            next
          end

          trimmed = entry.strip
          tokens << trimmed unless trimmed.empty?
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

        if (address = parse_ip(candidate)) && !candidate.include?("/")
          return address.to_s.downcase
        end

        if candidate.start_with?("[")
          host = host_from_url("http://#{candidate}")
          return host if host
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

      # Coerces one present list (storage shape) into an array of entries.
      #
      # Nothing is ever dropped: `false`, `nil`, numbers, hashes, and blank
      # strings inside an array stay as entries, and a scalar that is not a
      # string (`false`, `nil`, `42`) becomes a single entry, so validation
      # rejects them at write time and authentication refuses them at read
      # time. The only spelling of an intentionally empty list is `[]` (or
      # leaving the kind out). A string is accepted as a raw list
      # ("a.com, b.com"), but it must contain at least one entry.
      # @api private
      def coerce_list(value)
        case value
        when Array
          value.map { |entry| coerce_entry(entry) }
        when String
          entries = value.split(ENTRY_SEPARATOR).reject(&:empty?).map { |entry| coerce_entry(entry) }
          entries.empty? ? [value] : entries
        else
          [value]
        end
      rescue ArgumentError
        # A string with invalid encoding cannot be split; keep it as the
        # invalid entry it is.
        [value]
      end

      # @api private
      def blank_input?(entries)
        entries.nil? || (entries.is_a?(String) && entries.strip.empty?)
      rescue ArgumentError
        false
      end

      # @api private
      def coerce_entry(entry)
        return entry unless entry.is_a?(String)

        entry.strip.downcase
      rescue ArgumentError
        entry
      end

      # Whether a stored origin entry is shaped like a host or `*.host`.
      # @api private
      def valid_origin_entry?(entry)
        return false unless entry.is_a?(String)
        return true if !entry.include?("/") && parse_ip(entry)

        entry.bytesize <= 253 && entry.match?(ORIGIN_ENTRY_PATTERN)
      rescue ArgumentError
        false
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
      rescue IPAddr::Error
        nil
      end
    end

    # @param origins [Array<String>] Already-coerced origin entries.
    # @param ips [Array<String>] Already-coerced IP entries.
    # @param extras [Hash] Unrecognized keys, preserved so validation sees them.
    # @param malformed [Boolean] Whether coercion itself found an invalid shape.
    def initialize(origins: [], ips: [], extras: {}, malformed: false)
      @origins = deep_copy(origins, freeze_copy: true)
      @ips = deep_copy(ips, freeze_copy: true)
      @extras = deep_copy(extras, freeze_copy: true)
      @malformed = malformed || @extras.any? ||
                   @origins.any? { |entry| !self.class.valid_origin_entry?(entry) } ||
                   @ips.any? { |entry| !self.class.valid_ip_entry?(entry) }
      freeze
    end

    # Malformed data can only arrive through validation-bypassing writes or a
    # damaged database. Authentication always denies it.
    def malformed?
      @malformed
    end

    # @return [Boolean] true when this key may be used from anywhere.
    def unrestricted?
      !malformed? && origins.empty? && ips.empty?
    end

    # @return [Boolean] true when at least one list is locked.
    def restricted?
      !unrestricted?
    end

    # @return [Array<Symbol>] The restriction kinds actually in use.
    def kinds
      KINDS.reject { |kind| public_send(kind).empty? }
    end

    # The storage shape: known lists that have entries, plus any unrecognized
    # keys exactly as they were found.
    # @return [Hash]
    def to_h
      hash = {}
      hash["origins"] = deep_copy(origins) unless origins.empty?
      hash["ips"] = deep_copy(ips) unless ips.empty?
      hash.merge(deep_copy(extras))
    end

    alias as_json to_h

    # Does this request context satisfy every locked list?
    #
    # @param origin_host [String, nil] Host from Origin/Referer.
    # @param ip [String, nil] Client IP address.
    # @return [Boolean]
    def allows?(origin_host: nil, ip: nil)
      !malformed? && origin_allowed?(origin_host) && ip_allowed?(ip)
    end

    # @param host [String, nil] Bare host to check.
    # @return [Boolean] true when the origins list is empty or one entry matches.
    #   A locked list plus a nil/blank host refuses: fail closed.
    def origin_allowed?(host)
      return false if malformed?
      return true if origins.empty?

      candidate = host.to_s.strip.downcase
      return false if candidate.empty?
      candidate = self.class.parse_ip(candidate)&.to_s || candidate

      origins.any? { |entry| origin_entry_matches?(entry, candidate) }
    end

    # @param ip [String, nil] Client IP address.
    # @return [Boolean] true when the IP list is empty or one entry contains it.
    #   A locked list plus an unparseable address refuses: fail closed.
    def ip_allowed?(ip)
      return false if malformed?
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
      "#<#{self.class.name} origins=#{origins.inspect} ips=#{ips.inspect} malformed=#{malformed?.inspect}>"
    end

    private

    def deep_copy(value, freeze_copy: false)
      copy = case value
             when Hash
               value.to_h do |key, entry|
                 [deep_copy(key, freeze_copy: freeze_copy), deep_copy(entry, freeze_copy: freeze_copy)]
               end
             when Array
               value.map { |entry| deep_copy(entry, freeze_copy: freeze_copy) }
             when String
               value.dup
             else
               value
             end
      copy.freeze if freeze_copy
      copy
    end

    # `*.example.com` matches any subdomain at any depth, but never the apex —
    # Google's rule. List the apex separately when you want both.
    def origin_entry_matches?(entry, host)
      if entry.start_with?("*.")
        suffix = entry.delete_prefix("*")
        host.end_with?(suffix) && host.length > suffix.length
      else
        entry == host
      end
    end

    def ip_entry_matches?(entry, address)
      self.class.parse_ip(entry).include?(address)
    end
  end
end
