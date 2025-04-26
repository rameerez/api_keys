# frozen_string_literal: true

require "test_helper"

module ApiKeys
  module Services
    class TokenGeneratorTest < ApiKeys::Test
      test "generates token with default settings (prefix, length, base58)" do
        token = TokenGenerator.call
        assert_match(/^ak_test_/, token) # Default prefix for test env
        # Base58 length varies slightly, check it's roughly correct
        # 24 bytes entropy -> ~32-33 Base58 chars
        random_part_length = token.delete_prefix("ak_test_").length
        assert_includes 30..36, random_part_length, "Base58 token length out of expected range"
        assert token.match?(/^[a-zA-Z0-9]+$/), "Token contains non-Base58 characters"
      end

      test "generates token with custom prefix" do
        ApiKeys.configure { |config| config.token_prefix = -> { "custom_prefix_" } }
        token = TokenGenerator.call
        assert_match(/^custom_prefix_/, token)
      end

      test "generates token with custom length" do
        ApiKeys.configure { |config| config.token_length = 32 } # More entropy
        token = TokenGenerator.call
        # 32 bytes entropy -> ~43-44 Base58 chars
        random_part_length = token.delete_prefix("ak_test_").length
        assert_includes 40..48, random_part_length, "Base58 token length out of expected range for 32 bytes"
      end

      test "generates token with hex alphabet when configured" do
        ApiKeys.configure { |config| config.token_alphabet = :hex }
        token = TokenGenerator.call
        assert_match(/^ak_test_/, token)
        random_part = token.delete_prefix("ak_test_")
        assert_equal ApiKeys.configuration.token_length * 2, random_part.length # Hex is 2 chars per byte
        assert random_part.match?(/^[0-9a-f]+$/), "Token contains non-hex characters"
      end

      test "generates different tokens on subsequent calls" do
        token1 = TokenGenerator.call
        token2 = TokenGenerator.call
        refute_equal token1, token2
      end

      test "raises error for unsupported alphabet" do
        assert_raises ArgumentError do
          TokenGenerator.call(alphabet: :unsupported)
        end
      end
    end
  end
end
