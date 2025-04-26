# frozen_string_literal: true

require "bcrypt"
require "digest"

module ApiKeys
  module Services
    # Handles hashing (digesting) and verifying tokens based on configured strategy.
    class Digestor
      # Creates a digest of the given token using the configured strategy.
      #
      # @param token [String] The plaintext token.
      # @param strategy [Symbol] The hashing strategy (:bcrypt or :sha256).
      # @return [Hash] A hash containing the digest and the algorithm used.
      #   e.g., { digest: "...", algorithm: "bcrypt" }
      def self.digest(token:, strategy: ApiKeys.configuration.hash_strategy)
        case strategy
        when :bcrypt
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
        return false if token.blank? || stored_digest.blank?

        case strategy
        when :bcrypt
          begin
            bcrypt_object = BCrypt::Password.new(stored_digest)
            # BCrypt's `==` operator is designed for secure comparison
            bcrypt_object == token
          rescue BCrypt::Errors::InvalidHash
            # If the stored digest isn't a valid BCrypt hash, comparison fails
            false
          end
        when :sha256
          # Directly compare the SHA256 hash of the input token with the stored digest
          comparison_proc.call(stored_digest, Digest::SHA256.hexdigest(token))
        else
          # Strategy mismatch or unsupported strategy should fail comparison safely
          Rails.logger.error "[ApiKeys] Digestor comparison failed: Unsupported hash strategy '#{strategy}' for digest check." if defined?(Rails.logger)
          false
        end
      rescue ArgumentError => e
        # Catch potential errors from Digest or comparison proc
        Rails.logger.error "[ApiKeys] Digestor comparison error: #{e.message}" if defined?(Rails.logger)
        false
      end
    end
  end
end
