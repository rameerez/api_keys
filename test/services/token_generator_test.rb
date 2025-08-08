# frozen_string_literal: true

require "test_helper"

module ApiKeys
  module Services
    class TokenGeneratorTest < ApiKeys::Test
      test "generates token with default settings (prefix, length, base58)" do
        token = ApiKeys::Services::TokenGenerator.call
        assert_match(/^ak_/, token) # Default prefix
        # Base58 length varies slightly, check it's roughly correct
        # 24 bytes entropy -> ~32-33 Base58 chars
        random_part_length = token.delete_prefix("ak_").length
        assert_includes 28..60, random_part_length, "Base58 token length out of expected range"
        assert token.match?(/^[a-zA-Z0-9_]+$/), "Token contains unexpected characters"
      end

      test "generates token with custom prefix" do
        ApiKeys.configure { |config| config.token_prefix = -> { "custom_prefix_" } }
        token = ApiKeys::Services::TokenGenerator.call
        assert_match(/^custom_prefix_/, token)
      end

      test "generates token with custom length" do
        ApiKeys.configure { |config| config.token_length = 32 } # More entropy
        token = ApiKeys::Services::TokenGenerator.call
        # 32 bytes entropy -> ~43-44 Base58 chars; allow a generous range to account for encoding variance
        random_part_length = token.delete_prefix("ak_").length
        assert_includes 40..64, random_part_length, "Base58 token length out of expected range for 32 bytes"
      end

      test "generates token with hex alphabet when configured" do
        ApiKeys.configure { |config| config.token_alphabet = :hex }
        token = ApiKeys::Services::TokenGenerator.call
        assert_match(/^ak_/, token)
        random_part = token.delete_prefix("ak_")
        assert_equal ApiKeys.configuration.token_length * 2, random_part.length # Hex is 2 chars per byte
        assert random_part.match?(/^[0-9a-f]+$/), "Token contains non-hex characters"
      end

      test "generates different tokens on subsequent calls" do
        token1 = ApiKeys::Services::TokenGenerator.call
        token2 = ApiKeys::Services::TokenGenerator.call
        refute_equal token1, token2
      end

      test "raises error for unsupported alphabet" do
        assert_raises ArgumentError do
          ApiKeys::Services::TokenGenerator.call(alphabet: :unsupported)
        end
      end
    end
  end
end
