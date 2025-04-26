# frozen_string_literal: true

require "test_helper"

module ApiKeys
  module Services
    class DigestorTest < ApiKeys::Test
      def setup
        super
        @token = TokenGenerator.call # Generate a realistic token
      end

      # === .digest ===

      test ".digest uses bcrypt by default" do
        result = Digestor.digest(token: @token)
        assert_equal "bcrypt", result[:algorithm]
        assert BCrypt::Password.valid_hash?(result[:digest])
        assert BCrypt::Password.new(result[:digest]) == @token
      end

      test ".digest uses bcrypt when specified" do
        result = Digestor.digest(token: @token, strategy: :bcrypt)
        assert_equal "bcrypt", result[:algorithm]
        assert BCrypt::Password.valid_hash?(result[:digest])
        assert BCrypt::Password.new(result[:digest]) == @token
      end

      test ".digest uses sha256 when specified" do
        result = Digestor.digest(token: @token, strategy: :sha256)
        assert_equal "sha256", result[:algorithm]
        assert_equal Digest::SHA256.hexdigest(@token), result[:digest]
      end

      test ".digest raises error for unsupported strategy" do
        assert_raises ArgumentError do
          Digestor.digest(token: @token, strategy: :md5)
        end
      end

      # === .match? ===

      test ".match? returns true for correct bcrypt token" do
        digest_info = Digestor.digest(token: @token, strategy: :bcrypt)
        assert Digestor.match?(token: @token, stored_digest: digest_info[:digest], strategy: :bcrypt)
      end

      test ".match? returns false for incorrect bcrypt token" do
        digest_info = Digestor.digest(token: @token, strategy: :bcrypt)
        refute Digestor.match?(token: "incorrect_token", stored_digest: digest_info[:digest], strategy: :bcrypt)
      end

      test ".match? returns false for invalid bcrypt hash" do
        refute Digestor.match?(token: @token, stored_digest: "invalid_bcrypt_hash", strategy: :bcrypt)
      end

      test ".match? returns true for correct sha256 token" do
        digest_info = Digestor.digest(token: @token, strategy: :sha256)
        assert Digestor.match?(token: @token, stored_digest: digest_info[:digest], strategy: :sha256)
      end

      test ".match? returns false for incorrect sha256 token" do
        digest_info = Digestor.digest(token: @token, strategy: :sha256)
        refute Digestor.match?(token: "incorrect_token", stored_digest: digest_info[:digest], strategy: :sha256)
      end

      test ".match? uses configured secure_compare_proc for sha256" do
        digest_info = Digestor.digest(token: @token, strategy: :sha256)
        mock_proc = Minitest::Mock.new
        # Expect secure_compare to be called with the stored digest and the *hashed* input token
        mock_proc.expect(:call, true, [digest_info[:digest], Digest::SHA256.hexdigest(@token)])

        assert Digestor.match?(token: @token, stored_digest: digest_info[:digest], strategy: :sha256, comparison_proc: mock_proc)
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
        bcrypt_digest = Digestor.digest(token: @token, strategy: :bcrypt)[:digest]
        sha256_digest = Digestor.digest(token: @token, strategy: :sha256)[:digest]

        refute Digestor.match?(token: @token, stored_digest: bcrypt_digest, strategy: :sha256)
        refute Digestor.match?(token: @token, stored_digest: sha256_digest, strategy: :bcrypt)
      end

      test ".match? returns false for unsupported strategy" do
        digest_info = Digestor.digest(token: @token, strategy: :bcrypt)
        refute Digestor.match?(token: @token, stored_digest: digest_info[:digest], strategy: :md5)
      end
    end
  end
end
