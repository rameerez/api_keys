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
      # name of a tool) and its parameters, with the names in order and an
      # uploaded file by its bytes, so the same request has the same digest.
      def digest_of(*parts, parameters)
        Digest::SHA256.hexdigest([*parts, canonical(parameters).to_json].join("\n"))
      end

      def canonical(value)
        case value
        when Hash then value.to_h { |name, inner| [name.to_s, canonical(inner)] }.sort.to_h
        when Array then value.map { |inner| canonical(inner) }
        else uploaded_file_digest(value) || value
        end
      end

      # Yields the API key's row of +key+, locked, inside the transaction that
      # the caller's write joins. Raises Busy while another request holds it.
      def hold(api_key, key)
        busy_on_lock_wait { claim(api_key, key) }
        transaction(requires_new: true) { yield locked(api_key, key) }
      end

      # The row, locked for the rest of the transaction. The wait is at most
      # LOCK_TIMEOUT seconds on PostgreSQL and MySQL. SQLite has no row
      # locks: there an UPDATE takes the database's write lock first, and the
      # wait is the database's busy timeout.
      def locked(api_key, key)
        rows = where(api_key: api_key, key: key)
        busy_on_lock_wait do
          waiting_at_most_lock_timeout do
            rows.update_all(updated_at: Time.current) if connection.adapter_name.match?(/sqlite/i)
            rows.lock.take || raise(Busy) # deleted since it was claimed: the client retries
          end
        end
      end

      private

      # Claims the key's row in a commit of its own. A key that exists is
      # read without a lock, so a retry never waits here for the request
      # that holds it: it waits in `locked`, at most LOCK_TIMEOUT. A day-old
      # key is deleted and claimed afresh.
      def claim(api_key, key)
        rows = where(api_key: api_key, key: key)
        existing = rows.take
        return existing if existing && existing.created_at > RETENTION.ago

        rows.expired.delete_all if existing
        # The row keeps the API key's id, never its token.
        create_or_find_by!(api_key_id: api_key.id, key: key)
      end

      def uploaded_file_digest(value)
        return unless value.respond_to?(:tempfile) && value.respond_to?(:original_filename)

        Digest::SHA256.file(value.tempfile.path).hexdigest
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
