# frozen_string_literal: true

require "securerandom"
require "base58"

module ApiKeys
  module Services
    # Generates secure, random API tokens according to configured settings.
    class TokenGenerator
      MIN_RANDOM_BYTES = 16
      MAX_RANDOM_BYTES = 64
      MAX_PREFIX_BYTESIZE = 64

      # Generates a new token string.
      #
      # @param length [Integer] The desired byte length of the random part (before encoding).
      # @param prefix [String] The prefix to prepend to the token.
      # @param alphabet [Symbol] The encoding alphabet (:base58 or :hex).
      # @return [String] The generated token including the prefix.
      def self.call(length: nil, prefix: nil, alphabet: nil)
        length ||= ApiKeys.configuration.token_length
        prefix ||= ApiKeys.configuration.resolved_token_prefix
        alphabet ||= ApiKeys.configuration.token_alphabet

        validate_length!(length)
        validate_prefix!(prefix)
        validate_alphabet!(alphabet)

        random_bytes = SecureRandom.bytes(length)

        random_part = case alphabet
                      when :base58
                        Base58.binary_to_base58(random_bytes, :bitcoin)
                      when :hex
                        random_bytes.unpack1("H*") # Equivalent to SecureRandom.hex
                      else
                        raise ArgumentError, "Unsupported token alphabet: #{alphabet}. Use :base58 or :hex."
                      end

        "#{prefix}#{random_part}"
      end

      def self.validate_length!(length)
        return if length.is_a?(Integer) && length.between?(MIN_RANDOM_BYTES, MAX_RANDOM_BYTES)

        raise ArgumentError,
          "Token length must be an Integer between #{MIN_RANDOM_BYTES} and #{MAX_RANDOM_BYTES} random bytes."
      end

      def self.validate_prefix!(prefix)
        valid = prefix.is_a?(String) && prefix.present? && prefix.valid_encoding? &&
          prefix.bytesize <= MAX_PREFIX_BYTESIZE &&
          prefix.each_codepoint.none? { |codepoint| codepoint <= 0x20 || codepoint == 0x7f }
        return if valid

        raise ArgumentError,
          "Token prefix must be a non-blank string of at most #{MAX_PREFIX_BYTESIZE} bytes without whitespace or control characters."
      rescue ArgumentError
        raise ArgumentError,
          "Token prefix must be a non-blank string of at most #{MAX_PREFIX_BYTESIZE} bytes without whitespace or control characters."
      end

      def self.validate_alphabet!(alphabet)
        return if %i[base58 hex].include?(alphabet)

        raise ArgumentError, "Unsupported token alphabet: #{alphabet}. Use :base58 or :hex."
      end

      private_class_method :validate_length!, :validate_prefix!, :validate_alphabet!
    end
  end
end
