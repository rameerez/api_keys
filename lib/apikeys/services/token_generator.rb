# frozen_string_literal: true

require "securerandom"
require "base58"

module Apikeys
  module Services
    # Generates secure, random API tokens according to configured settings.
    class TokenGenerator
      # Generates a new token string.
      #
      # @param length [Integer] The desired byte length of the random part (before encoding).
      # @param prefix [String] The prefix to prepend to the token.
      # @param alphabet [Symbol] The encoding alphabet (:base58 or :hex).
      # @return [String] The generated token including the prefix.
      def self.call(length: Apikeys.configuration.token_length, prefix: Apikeys.configuration.token_prefix.call, alphabet: Apikeys.configuration.token_alphabet)
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
    end
  end
end
