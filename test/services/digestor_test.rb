# frozen_string_literal: true

require "test_helper"

module ApiKeys
  module Services
    class DigestorTest < ApiKeys::Test
      def setup
        super
        @token = ApiKeys::Services::TokenGenerator.call # Generate a realistic token
      end

      # === .digest ===

      test ".digest uses sha256 by default" do
        result = ApiKeys::Services::Digestor.digest(token: @token)
        assert_equal "sha256", result[:algorithm]
        assert_equal Digest::SHA256.hexdigest(@token), result[:digest]
      end

      test ".digest uses bcrypt when specified" do
        result = ApiKeys::Services::Digestor.digest(token: @token, strategy: :bcrypt)
        assert_equal "bcrypt", result[:algorithm]
        assert BCrypt::Password.valid_hash?(result[:digest])
        assert BCrypt::Password.new(result[:digest]) == @token
      end

      test ".digest uses sha256 when specified" do
        result = ApiKeys::Services::Digestor.digest(token: @token, strategy: :sha256)
        assert_equal "sha256", result[:algorithm]
        assert_equal Digest::SHA256.hexdigest(@token), result[:digest]
      end

      test ".digest raises error for unsupported strategy" do
        assert_raises ArgumentError do
          ApiKeys::Services::Digestor.digest(token: @token, strategy: :md5)
        end
      end

      # === .match? ===

      test ".match? returns true for correct bcrypt token" do
        digest_info = ApiKeys::Services::Digestor.digest(token: @token, strategy: :bcrypt)
        assert ApiKeys::Services::Digestor.match?(token: @token, stored_digest: digest_info[:digest], strategy: :bcrypt)
      end

      test ".match? returns false for incorrect bcrypt token" do
        digest_info = ApiKeys::Services::Digestor.digest(token: @token, strategy: :bcrypt)
        refute ApiKeys::Services::Digestor.match?(token: "incorrect_token", stored_digest: digest_info[:digest], strategy: :bcrypt)
      end

      test ".match? returns false for invalid bcrypt hash" do
        refute ApiKeys::Services::Digestor.match?(token: @token, stored_digest: "invalid_bcrypt_hash", strategy: :bcrypt)
      end

      test ".match? fails closed for bcrypt hashes with invalid costs" do
        malformed_digest = "$2b$99$" + ("a" * 53)

        refute ApiKeys::Services::Digestor.match?(
          token: @token,
          stored_digest: malformed_digest,
          strategy: :bcrypt
        )
      end

      test ".match? rejects otherwise structured bcrypt hashes with excessive costs" do
        excessive_cost_digest = "$2b$17$" + ("a" * 53)

        refute ApiKeys::Services::Digestor.valid_bcrypt_digest?(excessive_cost_digest)
        refute ApiKeys::Services::Digestor.match?(
          token: @token,
          stored_digest: excessive_cost_digest,
          strategy: :bcrypt
        )
      end

      test "bcrypt generation rejects excessive configured costs before hashing" do
        original_cost = BCrypt::Engine.cost
        BCrypt::Engine.cost = ApiKeys::Services::Digestor::BCRYPT_MAX_SAFE_COST + 1

        assert_raises(ArgumentError) do
          ApiKeys::Services::Digestor.digest(token: @token, strategy: :bcrypt)
        end
      ensure
        BCrypt::Engine.cost = original_cost
      end

      test "sha256 comparison proc failures fail closed" do
        digest = Digest::SHA256.hexdigest(@token)
        comparison = ->(*) { raise IOError, "comparison backend unavailable" }

        refute ApiKeys::Services::Digestor.match?(
          token: @token,
          stored_digest: digest,
          strategy: :sha256,
          comparison_proc: comparison
        )
      end

      test "sha256 comparison accepts only literal true" do
        digest = Digest::SHA256.hexdigest(@token)

        [Object.new, "true", 1].each do |truthy_value|
          refute ApiKeys::Services::Digestor.match?(
            token: @token,
            stored_digest: digest,
            strategy: :sha256,
            comparison_proc: ->(*) { truthy_value }
          )
        end
      end

      test ".match? returns true for correct sha256 token" do
        digest_info = ApiKeys::Services::Digestor.digest(token: @token, strategy: :sha256)
        assert ApiKeys::Services::Digestor.match?(token: @token, stored_digest: digest_info[:digest], strategy: :sha256)
      end

      test ".match? returns false for incorrect sha256 token" do
        digest_info = ApiKeys::Services::Digestor.digest(token: @token, strategy: :sha256)
        refute ApiKeys::Services::Digestor.match?(token: "incorrect_token", stored_digest: digest_info[:digest], strategy: :sha256)
      end

      test ".match? uses configured secure_compare_proc for sha256" do
        digest_info = ApiKeys::Services::Digestor.digest(token: @token, strategy: :sha256)
        mock_proc = Minitest::Mock.new
        # Expect secure_compare to be called with the stored digest and the *hashed* input token
        mock_proc.expect(:call, true, [digest_info[:digest], Digest::SHA256.hexdigest(@token)])

        assert ApiKeys::Services::Digestor.match?(token: @token, stored_digest: digest_info[:digest], strategy: :sha256, comparison_proc: mock_proc)
        mock_proc.verify
      end

      test ".match? returns false for blank token or digest" do
        digest_info = Digestor.digest(token: @token, strategy: :bcrypt)
        refute Digestor.match?(token: "", stored_digest: digest_info[:digest], strategy: :bcrypt)
        refute Digestor.match?(token: nil, stored_digest: digest_info[:digest], strategy: :bcrypt)
        refute Digestor.match?(token: @token, stored_digest: "", strategy: :bcrypt)
        refute Digestor.match?(token: @token, stored_digest: nil, strategy: :bcrypt)
      end

      test ".match? returns false for mismatched strategy" do
        bcrypt_digest = ApiKeys::Services::Digestor.digest(token: @token, strategy: :bcrypt)[:digest]
        sha256_digest = ApiKeys::Services::Digestor.digest(token: @token, strategy: :sha256)[:digest]

        refute Digestor.match?(token: @token, stored_digest: bcrypt_digest, strategy: :sha256)
        refute Digestor.match?(token: @token, stored_digest: sha256_digest, strategy: :bcrypt)
      end

      test ".match? returns false for unsupported strategy" do
        digest_info = ApiKeys::Services::Digestor.digest(token: @token, strategy: :bcrypt)
        refute ApiKeys::Services::Digestor.match?(token: @token, stored_digest: digest_info[:digest], strategy: :md5)
      end

      test "bcrypt digest rejects secrets beyond bcrypt's safe byte limit" do
        oversized = "a" * (ApiKeys::Services::Digestor::BCRYPT_MAX_SECRET_BYTESIZE + 1)

        error = assert_raises(ArgumentError) do
          ApiKeys::Services::Digestor.digest(token: oversized, strategy: :bcrypt)
        end

        refute_includes error.message, oversized
      end

      test "bcrypt matching rejects values that only match after truncation" do
        max = ApiKeys::Services::Digestor::BCRYPT_MAX_SECRET_BYTESIZE
        prefix = "a" * max
        stored_digest = BCrypt::Password.create(prefix).to_s

        refute ApiKeys::Services::Digestor.match?(
          token: "#{prefix}different-suffix",
          stored_digest: stored_digest,
          strategy: :bcrypt
        )
      end

      test "digest rejects non-string tokens" do
        assert_raises(ArgumentError) do
          ApiKeys::Services::Digestor.digest(token: Object.new, strategy: :sha256)
        end
      end
    end
  end
end
