# frozen_string_literal: true

require "active_record"
require "digest"
require "json"

module ApiKeys
  # One write under one API key's Idempotency-Key header
  # (draft-ietf-httpapi-idempotency-key-header; ApiKeys::Idempotency).
  #
  # The key's row is claimed first, in a commit of its own. The write then
  # runs in one transaction with the row locked, and the write, the rows it
  # adds (an audit entry) and the key's answer (the status and the record the
  # write made or changed) commit together, or nothing does. So an answered
  # key means the write happened, and a key without an answer means it did
  # not:
  #
  #   answered, the same request     the retry gets the record as it is now
  #                                  and changes nothing
  #   answered, another request      refused
  #   no answer, locked              another request runs it now: Busy
  #   no answer, free                a refused write or a crash: it runs
  #
  # No answer keeps a body, so a secret that was shown once is never stored.
  # Each API key has its own keys, kept for a day.
  class IdempotencyKey < ActiveRecord::Base
    self.table_name = "api_keys_idempotency_keys"

    HEADER = "Idempotency-Key"
    MAX_LENGTH = 255
    RETENTION = 24.hours
    LOCK_TIMEOUT = 2 # seconds a retry waits for the request that holds the key

    # Raised while another request holds the key.
    class Busy < ApiKeys::Error; end

    belongs_to :api_key, class_name: "ApiKeys::ApiKey"
    belongs_to :resource, polymorphic: true, optional: true

    validates :key, presence: true, length: { maximum: MAX_LENGTH }

    scope :expired, -> { where(created_at: ...RETENTION.ago) }

    class << self
      # Deletes the keys older than a day.
      # @return [Integer] How many were deleted.
      def prune!
        expired.delete_all
      end

      # The digest of a request: its parts (the method and the path, or the
      # name of a tool) and its parameters, with the names in order, so the
      # same request has the same digest.
      def digest_of(*parts, parameters)
        Digest::SHA256.hexdigest([*parts, canonical(parameters).to_json].join("\n"))
      end

      # Every value becomes a pair of a tag and its content, so values of
      # different kinds never encode alike: an upload is never equal to a
      # text that holds its digest, or to a hash that looks like one. An
      # upload counts by its bytes, its file name and its content type. A
      # hash that names a key twice, as a symbol and as a text, is refused:
      # its order would decide the digest.
      def canonical(value)
        if value.is_a?(Hash)
          pairs = value.map { |name, inner| [name.to_s, canonical(inner)] }
          duplicates = pairs.map(&:first).tally.select { |_name, count| count > 1 }.keys
          raise ArgumentError, "the parameters name #{duplicates.join(', ')} twice" if duplicates.any?

          ["object", pairs.sort_by(&:first)]
        elsif value.is_a?(Array)
          ["array", value.map { |inner| canonical(inner) }]
        elsif upload?(value)
          ["upload", Digest::SHA256.file(value.tempfile.path).hexdigest, value.original_filename.to_s, value.content_type.to_s]
        else
          ["value", value]
        end
      end

      # Yields the API key's row of +key+, locked, inside the transaction that
      # the caller's write joins. Raises Busy while another request holds it.
      #
      # It runs outside every open transaction, so that the claim commits on
      # its own: inside one, the claim and the answer are a savepoint, and
      # the outer rollback removes both. Only transactional tests may run it
      # inside a transaction, with `config.idempotency_in_test_transactions`.
      def hold(api_key, key)
        if connection.transaction_open? && !ApiKeys.configuration.idempotency_in_test_transactions?
          raise ApiKeys::Error, "ApiKeys::IdempotencyKey.hold runs outside database transactions, so that the key's " \
                                "claim commits on its own: run run_once_per_idempotency_key outside any transaction. " \
                                "Transactional tests set config.idempotency_in_test_transactions = true."
        end

        claim(api_key, key)
        transaction(requires_new: true) { yield locked(api_key, key) }
      end

      # The row, locked for the rest of the transaction. The wait is at most
      # LOCK_TIMEOUT seconds on PostgreSQL and MySQL. SQLite has no row
      # locks: there an UPDATE takes the database's write lock first, and the
      # wait is the database's busy timeout.
      def locked(api_key, key)
        rows = where(api_key_id: api_key.id, key: key)
        busy_on_lock_wait do
          waiting_at_most_lock_timeout do
            rows.update_all(updated_at: Time.current) if connection.adapter_name.match?(/sqlite/i)
            rows.lock.take || raise(Busy) # deleted since it was claimed: the client retries
          end
        end
      end

      private

      # Claims the key's row in a transaction of its own. A key that exists
      # is read without a lock, so a retry never waits here for the request
      # that holds it: it waits in `locked`. A new key is inserted, and two
      # first requests with the same key wait for each other's insert at
      # most LOCK_TIMEOUT. A day-old key is deleted and claimed afresh. The
      # read comes before the transaction, so on MySQL the insert's fallback
      # read sees the row that the other request committed.
      def claim(api_key, key)
        rows = where(api_key_id: api_key.id, key: key)
        existing = busy_on_lock_wait { rows.take }
        return existing if existing && existing.created_at > RETENTION.ago

        busy_on_lock_wait do
          transaction(requires_new: true) do
            waiting_at_most_lock_timeout do
              rows.expired.delete_all if existing
              # The row keeps the API key's id, never its token.
              create_or_find_by!(api_key_id: api_key.id, key: key)
            end
          end
        end
      end

      # ActionDispatch::Http::UploadedFile, and the files of Rack::Test.
      def upload?(value)
        %i[tempfile original_filename content_type].all? { |name| value.respond_to?(name) }
      end

      def busy_on_lock_wait
        yield
      rescue ActiveRecord::LockWaitTimeout, ActiveRecord::StatementTimeout
        raise Busy
      rescue ActiveRecord::StatementInvalid => error
        # Rails before 8.0 does not name SQLite's "database is locked".
        raise Busy if defined?(::SQLite3::BusyException) && error.cause.is_a?(::SQLite3::BusyException)

        raise
      end

      # The statements hold no input: LOCK_TIMEOUT is 2 seconds in each.
      def waiting_at_most_lock_timeout
        case connection.adapter_name
        when /postg/i
          # SET LOCAL ends with the transaction, or with a lock wait that
          # fails it. After the lock, the write waits as it always does.
          connection.execute("SET LOCAL lock_timeout = '2s'")
          yield.tap { connection.execute("SET LOCAL lock_timeout TO DEFAULT") }
        when /mysql|trilogy/i
          connection.execute("SET @api_keys_lock_wait = @@SESSION.innodb_lock_wait_timeout, SESSION innodb_lock_wait_timeout = 2")
          begin
            yield
          ensure
            connection.execute("SET SESSION innodb_lock_wait_timeout = @api_keys_lock_wait")
          end
        else
          yield
        end
      end
    end

    def answered?
      !response_status.nil?
    end

    def answer!(status, resource)
      raise ArgumentError, "a write under an Idempotency-Key answers with the record it made or changed" unless resource

      update!(response_status: status, resource: resource)
    end
  end
end
