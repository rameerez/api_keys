# frozen_string_literal: true

require "bcrypt"
require "digest"

module ApiKeys
  module Services
    # Handles hashing (digesting) and verifying tokens based on configured strategy.
    class Digestor
      BCRYPT_MAX_SECRET_BYTESIZE = if BCrypt::Engine.const_defined?(:MAX_SECRET_BYTESIZE)
                                      BCrypt::Engine::MAX_SECRET_BYTESIZE
                                    else
                                      72
                                    end
      # Costs above this value can turn a malformed/imported database row into
      # a multi-second (or worse) CPU denial of service during authentication.
      # The default bcrypt cost is comfortably below this ceiling.
      BCRYPT_MAX_SAFE_COST = 16
      MAX_TOKEN_BYTESIZE = 512

      # Creates a digest of the given token using the configured strategy.
      #
      # @param token [String] The plaintext token.
      # @param strategy [Symbol] The hashing strategy (:bcrypt or :sha256).
      # @return [Hash] A hash containing the digest and the algorithm used.
      #   e.g., { digest: "...", algorithm: "bcrypt" }
      def self.digest(token:, strategy: ApiKeys.configuration.hash_strategy)
        validate_token!(token)

        case strategy
        when :bcrypt
          if token.bytesize > BCRYPT_MAX_SECRET_BYTESIZE
            raise ArgumentError,
              "BCrypt tokens must not exceed #{BCRYPT_MAX_SECRET_BYTESIZE} bytes because BCrypt truncates longer inputs."
          end

          unless safe_bcrypt_cost?(BCrypt::Engine.cost)
            raise ArgumentError,
              "BCrypt cost must be between #{BCrypt::Engine::MIN_COST} and #{BCRYPT_MAX_SAFE_COST}."
          end

          # BCrypt handles salt generation internally
          digest = BCrypt::Password.create(token, cost: BCrypt::Engine.cost)
          { digest: digest.to_s, algorithm: "bcrypt" }
        when :sha256
          # Note: Simple SHA256 without salt/pepper. Consider enhancing if needed.
          # BCrypt is generally preferred for password/token hashing.
          digest = Digest::SHA256.hexdigest(token)
          { digest: digest, algorithm: "sha256" }
        else
          raise ArgumentError, "Unsupported hash strategy: #{strategy}. Use :bcrypt or :sha256."
        end
      end

      # Securely compares a plaintext token against a stored digest.
      # Uses the configured secure comparison proc and hash strategy.
      #
      # @param token [String] The plaintext token provided by the user/client.
      # @param stored_digest [String] The hashed digest stored in the database.
      # @param strategy [Symbol] The hashing strategy used to create the stored_digest.
      # @param comparison_proc [Proc] The secure comparison function.
      # @return [Boolean] True if the token matches the digest, false otherwise.
      def self.match?(token:, stored_digest:, strategy: ApiKeys.configuration.hash_strategy, comparison_proc: ApiKeys.configuration.secure_compare_proc)
        return false unless valid_match_inputs?(token, stored_digest)

        case strategy
        when :bcrypt
          return false if token.bytesize > BCRYPT_MAX_SECRET_BYTESIZE

          bcrypt_object = validated_bcrypt_password(stored_digest)
          return false unless bcrypt_object

          # BCrypt's `==` operator is designed for secure comparison.
          bcrypt_object == token
        when :sha256
          # Directly compare the SHA256 hash of the input token with the stored digest
          return false unless stored_digest.match?(/\A\h{64}\z/)

          # A custom comparator is security-sensitive. Accept only the literal
          # boolean true so truthy sentinel/error values can never authenticate.
          comparison_proc.call(stored_digest, Digest::SHA256.hexdigest(token)) == true
        else
          # Strategy mismatch or unsupported strategy should fail comparison safely
          if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
            Rails.logger.error "[ApiKeys] Digestor comparison failed: Unsupported hash strategy '#{strategy}' for digest check."
          end
          false
        end
      rescue StandardError => error
        # A malformed digest or application-supplied comparison proc must never
        # turn an authentication failure into an exception or an availability issue.
        if defined?(Rails) && Rails.respond_to?(:logger) && Rails.logger
          Rails.logger.error "[ApiKeys] Digestor comparison error (#{error.class})."
        end
        false
      end

      # Returns whether a stored bcrypt digest is structurally valid and has a
      # bounded cost that is safe to evaluate on an authentication request.
      def self.valid_bcrypt_digest?(stored_digest)
        !validated_bcrypt_password(stored_digest).nil?
      end

      def self.validate_token!(token)
        valid = token.is_a?(String) && token.present? && token.valid_encoding? && token.bytesize <= MAX_TOKEN_BYTESIZE
        return if valid

        raise ArgumentError, "Token must be a non-blank valid string of at most #{MAX_TOKEN_BYTESIZE} bytes."
      end

      def self.valid_match_inputs?(token, stored_digest)
        token.is_a?(String) && token.present? && token.valid_encoding? && token.bytesize <= MAX_TOKEN_BYTESIZE &&
          stored_digest.is_a?(String) && stored_digest.present? && stored_digest.valid_encoding? &&
          stored_digest.bytesize <= 128
      rescue ArgumentError
        false
      end

      def self.validated_bcrypt_password(stored_digest)
        return nil unless stored_digest.is_a?(String) && stored_digest.valid_encoding? && stored_digest.bytesize <= 128

        password = BCrypt::Password.new(stored_digest)
        password if safe_bcrypt_cost?(password.cost)
      rescue BCrypt::Error, ArgumentError
        nil
      end

      def self.safe_bcrypt_cost?(cost)
        cost.is_a?(Integer) && cost.between?(BCrypt::Engine::MIN_COST, BCRYPT_MAX_SAFE_COST)
      end

      private_class_method :validate_token!, :valid_match_inputs?, :validated_bcrypt_password, :safe_bcrypt_cost?
    end
  end
end
