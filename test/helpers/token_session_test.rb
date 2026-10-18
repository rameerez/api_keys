# frozen_string_literal: true

require "test_helper"
require "active_support/message_encryptor"
require "timeout"
require "tmpdir"

module ApiKeys
  module Helpers
    class TokenSessionTest < ApiKeys::Test
      def setup
        super
        @session = {}
        encryption_key = "k" * ActiveSupport::MessageEncryptor.key_len("aes-256-gcm")
        @encryptor = ActiveSupport::MessageEncryptor.new(
          encryption_key,
          cipher: "aes-256-gcm",
          serializer: JSON
        )
        TokenSession.stubs(:token_encryptor).returns(@encryptor)
      end

      def use_cache(cache)
        Rails.stubs(:cache).returns(cache)
      end

      # The durable claim stamps a real api_keys row, so every handoff these
      # tests bind to a key ID names a key that exists.
      def bound_key(token, id)
        ensure_key_row(id)
        Struct.new(:token, :id).new(token, id)
      end

      def ensure_key_row(id)
        return if ApiKeys::ApiKey.exists?(id)

        now = Time.current
        ApiKeys::ApiKey.insert_all!([{ id: id, prefix: "ak_test_", token_digest: "test-digest-#{id}",
                                       digest_algorithm: "sha256", last4: "test", created_at: now, updated_at: now }])
      end

      # Retrieves every copy at once, each from its own thread on its own
      # autocommit connection to the file database (see with_file_database),
      # and returns every Retrieval. The barrier opens only once every thread
      # holds a distinct connection, so the claims really race.
      def race_on_file_database(copies, api_key_id:)
        ApiKeys::ApiKey.column_names # load the schema once, before the threads
        checked_out = Queue.new
        go = Queue.new
        threads = copies.map do |copy|
          Thread.new do
            ApiKeys::ApiKey.connection_pool.with_connection do |connection|
              raise "a race thread must not share a transaction" if connection.transaction_open?

              checked_out << connection.object_id
              go.pop
              TokenSession.retrieve_once_with_status(copy, api_key_id: api_key_id)
            end
          end
        end
        connection_ids = Timeout.timeout(15) { Array.new(copies.size) { checked_out.pop } }
        assert_equal copies.size, connection_ids.uniq.size, "every thread holds its own connection before any retrieves"
        copies.size.times { go << true }
        threads.map(&:value)
      end

      # One winner; every loser was refused by the committed claim.
      def assert_one_winner(results, token)
        assert_equal [token], results.filter_map(&:token)
        assert_equal({ retrieved: 1, already_shown: results.size - 1 }, results.map(&:status).tally)
      end

      # Points ApiKeys::ApiKey at a fresh file-backed SQLite database for the
      # block, so threads get independent connections that share data (an
      # in-memory database is private to one connection). Restores the
      # shared test database afterwards.
      def with_file_database
        Dir.mktmpdir("api_keys_handoff") do |dir|
          ApiKeys::ApiKey.establish_connection(adapter: "sqlite3", database: File.join(dir, "handoff.sqlite3"),
                                               pool: 16, timeout: 10_000)
          ApiKeys::ApiKey.connection_pool.with_connection do |connection|
            connection.create_table :api_keys do |t|
              t.string :prefix, null: false
              t.string :token_digest, null: false
              t.string :digest_algorithm, null: false
              t.string :name
              t.references :owner, polymorphic: true, null: true
              t.text :scopes, default: "[]", null: false
              t.text :metadata, default: "{}", null: false
              t.text :restrictions, default: "{}", null: false
              t.datetime :expires_at
              t.datetime :last_used_at
              t.bigint :requests_count, default: 0, null: false
              t.datetime :last_refused_at
              t.bigint :refusals_count, default: 0, null: false
              t.string :last_refusal_code, limit: 64
              t.datetime :token_shown_at
              t.datetime :revoked_at
              t.string :last4, null: false, default: ""
              t.string :key_type
              t.string :environment
              t.timestamps
            end
          end
          ApiKeys::ApiKey.reset_column_information
          yield
        ensure
          ApiKeys::ApiKey.remove_connection
          ApiKeys::ApiKey.reset_column_information
        end
      end

      test "stores token from api_key object with token method" do
        api_key = mock("api_key")
        api_key.stubs(:respond_to?).with(:token).returns(true)
        api_key.stubs(:respond_to?).with(:id).returns(true)
        api_key.stubs(:token).returns("sk_test_abc123")
        api_key.stubs(:id).returns(42)

        result = TokenSession.store(@session, api_key)

        assert_equal "sk_test_abc123", result
        payload = @session[:api_keys_new_token]
        assert_equal TokenSession::HANDOFF_VERSION, payload["version"]
        assert_equal "42", payload["api_key_id"]
        assert_predicate payload["ciphertext"], :present?
        refute_includes payload.inspect, "sk_test_abc123"
      end

      test "stores token from object without token method using to_s" do
        result = TokenSession.store(@session, "plain_token_string")

        assert_equal "plain_token_string", result
        payload = @session[:api_keys_new_token]
        assert_equal TokenSession::HANDOFF_VERSION, payload["version"]
        assert_nil payload["api_key_id"]
        refute_includes payload.inspect, "plain_token_string"
      end

      test "stores token with custom session key" do
        api_key = mock("api_key")
        api_key.stubs(:respond_to?).with(:token).returns(true)
        api_key.stubs(:respond_to?).with(:id).returns(false)
        api_key.stubs(:token).returns("custom_token")

        TokenSession.store(@session, api_key, key: :my_custom_key)

        assert_equal TokenSession::HANDOFF_VERSION, @session[:my_custom_key]["version"]
        refute_includes @session[:my_custom_key].inspect, "custom_token"
        assert_nil @session[:api_keys_new_token]
      end

      test "retrieve_once returns and clears token" do
        TokenSession.store(@session, "stored_token")

        result = TokenSession.retrieve_once(@session)

        assert_equal "stored_token", result
        assert_nil @session[:api_keys_new_token]
      end

      test "retrieve_once returns nil when no token stored" do
        result = TokenSession.retrieve_once(@session)

        assert_nil result
      end

      test "retrieve_once with custom key" do
        TokenSession.store(@session, "my_token", key: :my_key)

        result = TokenSession.retrieve_once(@session, key: :my_key)

        assert_equal "my_token", result
        assert_nil @session[:my_key]
      end

      test "available? returns true when token present" do
        TokenSession.store(@session, "some_token")

        assert TokenSession.available?(@session)
      end

      test "available? returns false when token not present" do
        refute TokenSession.available?(@session)
      end

      test "available? returns false when token is blank" do
        @session[:api_keys_new_token] = {
          "version" => TokenSession::HANDOFF_VERSION,
          "ciphertext" => "invalid",
          "api_key_id" => nil
        }

        refute TokenSession.available?(@session)
      end

      test "available? with custom key" do
        TokenSession.store(@session, "token", key: :custom)

        assert TokenSession.available?(@session, key: :custom)
        refute TokenSession.available?(@session, key: :other)
      end

      test "retrieve_once only releases a token for its bound API key" do
        api_key = mock("api_key")
        api_key.stubs(:respond_to?).with(:token).returns(true)
        api_key.stubs(:respond_to?).with(:id).returns(true)
        api_key.stubs(:token).returns("key_one_secret")
        api_key.stubs(:id).returns(1)
        TokenSession.store(@session, api_key)

        assert_nil TokenSession.retrieve_once(@session, api_key_id: 2)
        assert_nil @session[:api_keys_new_token]
      end

      test "legacy unbound session values are not released when key binding is required" do
        @session[:api_keys_new_token] = "legacy_secret"

        assert_nil TokenSession.retrieve_once(@session, api_key_id: 1)
      end

      test "legacy plaintext payloads remain readable for an in-flight upgrade handoff" do
        ensure_key_row(7)
        @session[:api_keys_new_token] = { "token" => "legacy_secret", "api_key_id" => "7" }

        assert_equal "legacy_secret", TokenSession.retrieve_once(@session, api_key_id: 7)
        assert_nil @session[:api_keys_new_token]
      end

      test "a malformed version marker cannot downgrade to a legacy plaintext handoff" do
        [nil, false, 1, TokenSession::HANDOFF_VERSION.to_s].each do |version|
          @session[:api_keys_new_token] = {
            "version" => version,
            "token" => "downgrade_secret",
            "api_key_id" => "7"
          }

          refute TokenSession.available?(@session, api_key_id: 7)
          assert_nil TokenSession.retrieve_once(@session, api_key_id: 7)
        end
      end

      test "tampered encrypted handoffs fail closed and are cleared" do
        TokenSession.store(@session, "tamper_protected_token")
        ciphertext = @session[:api_keys_new_token]["ciphertext"].dup
        ciphertext.setbyte(0, ciphertext.getbyte(0) ^ 1)
        @session[:api_keys_new_token]["ciphertext"] = ciphertext

        refute TokenSession.available?(@session)
        assert_nil TokenSession.retrieve_once(@session)
        assert_nil @session[:api_keys_new_token]
      end

      test "encrypted handoffs expire quickly and fail closed" do
        TokenSession.store(@session, "short_lived_token")

        travel TokenSession::HANDOFF_TTL + 1.second do
          refute TokenSession.available?(@session)
          assert_nil TokenSession.retrieve_once(@session)
        end
        assert_nil @session[:api_keys_new_token]
      end

      test "production encryptor derives an authenticated-encryption key from the Rails application" do
        TokenSession.unstub(:token_encryptor)
        key_length = ActiveSupport::MessageEncryptor.key_len(TokenSession::ENCRYPTION_CIPHER)
        key_generator = mock("application key generator")
        key_generator.expects(:generate_key)
                     .with(TokenSession::ENCRYPTION_SALT, key_length)
                     .returns("r" * key_length)
        application = mock("Rails application")
        application.stubs(:key_generator).returns(key_generator)
        Rails.stubs(:application).returns(application)

        encryptor = TokenSession.send(:token_encryptor)
        ciphertext = encryptor.encrypt_and_sign(
          { "token" => "derived_key_token" },
          purpose: TokenSession::ENCRYPTION_PURPOSE
        )

        assert_equal({ "token" => "derived_key_token" }, encryptor.decrypt_and_verify(
          ciphertext,
          purpose: TokenSession::ENCRYPTION_PURPOSE
        ))
      end

      test "store rejects missing plaintext tokens" do
        api_key = mock("api_key")
        api_key.stubs(:respond_to?).with(:token).returns(true)
        api_key.stubs(:token).returns(nil)

        assert_raises(ArgumentError) { TokenSession.store(@session, api_key) }
        assert_empty @session
      end

      # =======================================================================
      # 0.5.1: one-time retrieval across copies of the session
      # 0.6.0: made durable by the key's token_shown_at column
      # =======================================================================

      test "a copied pre-consumption session cannot recover the token again" do
        use_cache(ActiveSupport::Cache::MemoryStore.new)
        TokenSession.store(@session, bound_key("copied_cookie_token", 7))
        copied_cookie = @session.deep_dup

        assert_equal "copied_cookie_token", TokenSession.retrieve_once(@session, api_key_id: 7)
        assert_nil TokenSession.retrieve_once(copied_cookie, api_key_id: 7)
        assert_nil copied_cookie[:api_keys_new_token], "the replayed copy is cleared as well"
      end

      test "concurrent retrievals on independent connections release the token once with a shared cache" do
        with_file_database do
          use_cache(ActiveSupport::Cache::MemoryStore.new)
          TokenSession.store(@session, bound_key("raced_token", 9))

          results = race_on_file_database(Array.new(8) { @session.deep_dup }, api_key_id: 9)

          assert_one_winner(results, "raced_token")
          assert ApiKeys::ApiKey.find(9).token_shown?, "the winning claim was committed"
        end
      end

      # Independent connections, each in autocommit, against a file database:
      # the committed claim alone decides, with no cache at all.
      test "independent connections racing outside any transaction release the token once" do
        with_file_database do
          use_cache(ActiveSupport::Cache::NullStore.new) # remembers nothing
          TokenSession.store(@session, bound_key("raced_without_cache_token", 19))
          late_copy = @session.deep_dup

          results = race_on_file_database(Array.new(8) { @session.deep_dup }, api_key_id: 19)

          assert_one_winner(results, "raced_without_cache_token")
          assert ApiKeys::ApiKey.find(19).token_shown?, "the winning claim was committed"
          retrieval = TokenSession.retrieve_once_with_status(late_copy, api_key_id: 19)
          assert_nil retrieval.token, "a copy replayed after the race finds the committed claim"
          assert_equal :already_shown, retrieval.status
        end
      end

      # =======================================================================
      # Retrieval inside a database transaction: the claim is only durable
      # once it commits, and the token would already be out by then, so a
      # retrieval inside a transaction is refused, whatever the cache.
      # =======================================================================

      CACHES_FOR_TRANSACTION_TESTS = {
        "no cache" => -> {},
        "NullStore" => -> { ActiveSupport::Cache::NullStore.new },
        "MemoryStore" => -> { ActiveSupport::Cache::MemoryStore.new }
      }.freeze

      test "inside a transaction the token is withheld and the handoff kept, whatever the cache" do
        CACHES_FOR_TRANSACTION_TESTS.each_with_index do |(label, build_cache), index|
          use_cache(build_cache.call)
          id = 320 + index
          session = {}
          TokenSession.store(session, bound_key("in_transaction_token_#{index}", id))
          copied_cookie = session.deep_dup
          warnings = []
          TokenSession.stubs(:log_warn).with { |message| warnings << message; true }
          retrieval = nil

          ApiKeys::ApiKey.transaction do
            retrieval = TokenSession.retrieve_once_with_status(session, api_key_id: id)
          end # the transaction commits, and still nothing was recorded

          assert_nil retrieval.token, label
          assert_equal :inside_transaction, retrieval.status, label
          assert session[:api_keys_new_token], "#{label}: the handoff stays for a retry outside the transaction"
          refute ApiKeys::ApiKey.find(id).token_shown?, "#{label}: nothing was claimed"
          assert_equal 1, warnings.size, label
          assert_includes warnings.first, "inside an open database transaction"
          refute_includes warnings.join, "in_transaction_token"

          # Outside the transaction the handoff is released once, durably.
          assert_equal "in_transaction_token_#{index}", TokenSession.retrieve_once(session, api_key_id: id), label
          assert_nil TokenSession.retrieve_once(copied_cookie, api_key_id: id), label
        end
      end

      test "a rolled-back retrieval cannot be replayed, from any copy or process, whatever the cache" do
        # Astra's reproduction: retrieve inside a transaction, roll back, then
        # replay a copy of the session taken before retrieval, here from this
        # process and from another one with its own process-local cache.
        CACHES_FOR_TRANSACTION_TESTS.each_with_index do |(label, build_cache), index|
          use_cache(build_cache.call)
          TokenSession.stubs(:log_warn)
          id = 330 + index
          session = {}
          TokenSession.store(session, bound_key("rollback_token_#{index}", id))
          copies = Array.new(2) { session.deep_dup }
          released = []

          ApiKeys::ApiKey.transaction do
            released << TokenSession.retrieve_once(session, api_key_id: id)
            raise ActiveRecord::Rollback
          end
          released << TokenSession.retrieve_once(copies[0], api_key_id: id)
          use_cache(build_cache.call) # another process
          released << TokenSession.retrieve_once(copies[1], api_key_id: id)
          released << TokenSession.retrieve_once(session, api_key_id: id)

          assert_equal ["rollback_token_#{index}"], released.compact, "#{label}: released once, never twice"
          assert_nil released.first, "#{label}: nothing left inside the transaction"
        end
      end

      test "after a rollback and a cache flush the token is still released only once" do
        cache = ActiveSupport::Cache::MemoryStore.new
        use_cache(cache)
        TokenSession.stubs(:log_warn)
        TokenSession.store(@session, bound_key("rollback_then_flush_token", 35))
        copies = Array.new(2) { @session.deep_dup }

        ApiKeys::ApiKey.transaction do
          assert_nil TokenSession.retrieve_once(@session, api_key_id: 35)
          raise ActiveRecord::Rollback
        end
        cache.clear

        assert_equal "rollback_then_flush_token", TokenSession.retrieve_once(copies[0], api_key_id: 35)
        cache.clear
        assert_nil TokenSession.retrieve_once(copies[1], api_key_id: 35)
      end

      # An abstract record on its own database: a transaction there is not a
      # transaction on the ApiKey connection.
      class OtherDatabaseRecord < ActiveRecord::Base
        self.abstract_class = true
      end

      test "a transaction on another database's connection does not refuse the retrieval" do
        use_cache(ActiveSupport::Cache::NullStore.new)
        OtherDatabaseRecord.establish_connection(adapter: "sqlite3", database: ":memory:")
        TokenSession.store(@session, bound_key("other_pool_token", 41))
        copied_cookie = @session.deep_dup
        retrieval = nil

        OtherDatabaseRecord.transaction do
          OtherDatabaseRecord.connection_pool.with_connection do |connection|
            assert connection.transaction_open?, "precondition: a transaction is open on the other pool"
          end
          retrieval = TokenSession.retrieve_once_with_status(@session, api_key_id: 41)
        end

        assert_equal :retrieved, retrieval.status
        assert ApiKeys::ApiKey.find(41).token_shown?, "the claim committed on the ApiKey connection"
        assert_nil TokenSession.retrieve_once(copied_cookie, api_key_id: 41)
      ensure
        OtherDatabaseRecord.remove_connection
      end

      test "any Active Record transaction on the ApiKey connection refuses the retrieval, nested ones too" do
        use_cache(ActiveSupport::Cache::MemoryStore.new)
        TokenSession.stubs(:log_warn)
        {
          "ApiKey.transaction" => ->(&work) { ApiKeys::ApiKey.transaction(&work) },
          "ActiveRecord::Base.transaction" => ->(&work) { ActiveRecord::Base.transaction(&work) },
          "a host model's transaction on the same database" => ->(&work) { User.transaction(&work) },
          "a savepoint (requires_new)" => lambda { |&work|
            ApiKeys::ApiKey.transaction { ApiKeys::ApiKey.transaction(requires_new: true, &work) }
          },
          "a non-joinable inner transaction" => lambda { |&work|
            User.transaction { ApiKeys::ApiKey.transaction(joinable: false, &work) }
          }
        }.each_with_index do |(label, wrap), index|
          id = 420 + index
          session = {}
          TokenSession.store(session, bound_key("nested_token_#{index}", id))
          retrieval = nil

          wrap.call { retrieval = TokenSession.retrieve_once_with_status(session, api_key_id: id) }

          assert_equal :inside_transaction, retrieval.status, label
          refute ApiKeys::ApiKey.find(id).token_shown?, label
          assert_equal "nested_token_#{index}", TokenSession.retrieve_once(session, api_key_id: id), label
        end
      end

      # The documented boundary: the check is Active Record's transaction
      # manager, so a transaction opened with raw SQL is not seen, and a
      # rollback of it undoes the claim. Pinned so the docs stay true.
      test "a transaction opened with raw SQL is not detected" do
        use_cache(ActiveSupport::Cache::NullStore.new)
        TokenSession.store(@session, bound_key("raw_sql_token", 43))
        retrieval = nil

        ApiKeys::ApiKey.connection_pool.with_connection do |connection|
          connection.execute("BEGIN")
          retrieval = TokenSession.retrieve_once_with_status(@session, api_key_id: 43)
          connection.execute("ROLLBACK")
        end

        assert_equal :retrieved, retrieval.status, "not detected"
        refute ApiKeys::ApiKey.find(43).token_shown?, "the raw rollback undid the claim"
      end

      test "inside a transaction a handoff an earlier claim used up is refused, not kept" do
        use_cache(ActiveSupport::Cache::NullStore.new)
        TokenSession.store(@session, bound_key("already_claimed_token", 37))
        copied_cookie = @session.deep_dup
        assert_equal "already_claimed_token", TokenSession.retrieve_once(@session, api_key_id: 37)
        retrieval = nil

        ApiKeys::ApiKey.transaction do
          retrieval = TokenSession.retrieve_once_with_status(copied_cookie, api_key_id: 37)
        end

        assert_equal :already_shown, retrieval.status
        assert_nil copied_cookie[:api_keys_new_token], "a spent handoff is not put back"
      end

      test "without the column a transaction changes nothing: the 0.5.1 behaviour" do
        TokenShownAtSchema.without_column do
          use_cache(ActiveSupport::Cache::NullStore.new)
          TokenSession.store(@session, bound_key("unmigrated_in_transaction_token", 38))
          released = nil

          ApiKeys::ApiKey.transaction do
            released = TokenSession.retrieve_once(@session, api_key_id: 38)
          end

          assert_equal "unmigrated_in_transaction_token", released
        end
      end

      test "a database error while checking for a transaction withholds the token" do
        use_cache(ActiveSupport::Cache::MemoryStore.new)
        TokenSession.store(@session, bound_key("unknown_transaction_token", 39))
        ApiKeys::ApiKey.stubs(:connection_pool).raises(ActiveRecord::ConnectionNotEstablished, "unknown_transaction_token")
        warnings = []
        TokenSession.stubs(:log_warn).with { |message| warnings << message; true }

        retrieval = TokenSession.retrieve_once_with_status(@session, api_key_id: 39)
        ApiKeys::ApiKey.unstub(:connection_pool)

        assert_nil retrieval.token
        assert_equal :withheld, retrieval.status
        refute_includes warnings.join, "unknown_transaction_token"
      end

      test "available? reports a handoff consumed through another copy as gone" do
        use_cache(ActiveSupport::Cache::MemoryStore.new)
        TokenSession.store(@session, bound_key("visible_token", 3))
        copied_cookie = @session.deep_dup

        assert TokenSession.available?(copied_cookie, api_key_id: 3)
        TokenSession.retrieve_once(@session, api_key_id: 3)

        refute TokenSession.available?(copied_cookie, api_key_id: 3)
      end

      test "any authentic retrieval attempt consumes the handoff, even a mismatched one" do
        use_cache(ActiveSupport::Cache::MemoryStore.new)
        TokenSession.store(@session, bound_key("probed_token", 5))
        copied_cookie = @session.deep_dup

        assert_nil TokenSession.retrieve_once(@session, api_key_id: 6)
        assert_nil TokenSession.retrieve_once(copied_cookie, api_key_id: 5)
        assert ApiKeys::ApiKey.find(5).token_shown?, "the mismatched attempt used the handoff up durably"
      end

      test "the consumption marker is atomic and outlives the handoff" do
        cache = ActiveSupport::Cache::MemoryStore.new
        use_cache(cache)
        TokenSession.store(@session, bound_key("marked_token", 4))
        cache.expects(:write)
             .with(regexp_matches(/\Aapi_keys:v1:token_handoff_consumed:[A-Za-z0-9_-]{32}\z/), true,
                   unless_exist: true, expires_in: TokenSession::HANDOFF_TTL)
             .returns(true)

        assert_equal "marked_token", TokenSession.retrieve_once(@session, api_key_id: 4)
      end

      test "each handoff carries its own random ID" do
        TokenSession.store(@session, bound_key("first_token", 1))
        first = @encryptor.decrypt_and_verify(@session[:api_keys_new_token]["ciphertext"],
                                              purpose: TokenSession::ENCRYPTION_PURPOSE)
        TokenSession.store(@session, bound_key("second_token", 2))
        second = @encryptor.decrypt_and_verify(@session[:api_keys_new_token]["ciphertext"],
                                               purpose: TokenSession::ENCRYPTION_PURPOSE)

        assert_match TokenSession::HANDOFF_ID_PATTERN, first["handoff_id"]
        refute_equal first["handoff_id"], second["handoff_id"]
        refute_includes @session.inspect, second["handoff_id"]
      end

      test "a cache failure withholds the token instead of risking a second release" do
        cache = ActiveSupport::Cache::MemoryStore.new
        cache.stubs(:write).raises(IOError, "cache unavailable")
        use_cache(cache)
        TokenSession.store(@session, bound_key("withheld_token", 8))

        retrieval = TokenSession.retrieve_once_with_status(@session, api_key_id: 8)
        assert_nil retrieval.token
        assert_equal :withheld, retrieval.status
      end

      test "available? reports nothing when the cache cannot be read" do
        cache = ActiveSupport::Cache::MemoryStore.new
        cache.stubs(:exist?).raises(IOError, "cache unavailable")
        use_cache(cache)
        TokenSession.store(@session, bound_key("unverifiable_token", 6))
        warnings = []
        TokenSession.stubs(:log_warn).with { |message| warnings << message; true }

        refute TokenSession.available?(@session, api_key_id: 6)
        assert_equal ["[ApiKeys Security] Token handoff consumption could not be checked (IOError)."], warnings
        refute_includes warnings.join, "unverifiable_token"
        assert @session[:api_keys_new_token], "a failed check is read-only and leaves the handoff in place"
        refute ApiKeys::ApiKey.find(6).token_shown?, "available? never claims the handoff"
      end

      test "a cache that refuses the marker withholds the token" do
        cache = ActiveSupport::Cache::MemoryStore.new
        cache.stubs(:write).returns(false) # what Redis and Memcached answer on error, too
        use_cache(cache)
        TokenSession.store(@session, bound_key("refused_token", 8))

        retrieval = TokenSession.retrieve_once_with_status(@session, api_key_id: 8)
        assert_nil retrieval.token
        assert_equal :withheld, retrieval.status, "no marker is present, so this is an error, not a replay"
      end

      # 0.5.1 pinned this as a limitation: the marker lived only in the cache,
      # so losing it re-opened replay. With token_shown_at it must not.
      test "losing the consumption marker no longer re-opens replay" do
        cache = ActiveSupport::Cache::MemoryStore.new
        use_cache(cache)
        TokenSession.store(@session, bound_key("marker_lost_token", 11))
        copied_cookie = @session.deep_dup
        second_copy = @session.deep_dup

        assert_equal "marker_lost_token", TokenSession.retrieve_once(@session, api_key_id: 11)
        assert_nil TokenSession.retrieve_once(copied_cookie, api_key_id: 11)

        cache.clear

        refute TokenSession.available?(second_copy, api_key_id: 11)
        retrieval = TokenSession.retrieve_once_with_status(second_copy, api_key_id: 11)
        assert_nil retrieval.token, "the durable claim stops the copy after the cache was flushed"
        assert_equal :already_shown, retrieval.status
      end

      # The 0.5.1 behaviour, kept for installations that have not migrated.
      test "without the token_shown_at column, losing the marker re-opens replay as in 0.5.1" do
        TokenShownAtSchema.without_column do
          cache = ActiveSupport::Cache::MemoryStore.new
          use_cache(cache)
          TokenSession.store(@session, bound_key("marker_lost_token", 11))
          copied_cookie = @session.deep_dup
          second_copy = @session.deep_dup
          late_copy = @session.deep_dup

          assert_equal "marker_lost_token", TokenSession.retrieve_once(@session, api_key_id: 11)
          assert_nil TokenSession.retrieve_once(copied_cookie, api_key_id: 11), "replay is stopped while the marker exists"

          cache.clear

          assert_equal "marker_lost_token", TokenSession.retrieve_once(second_copy, api_key_id: 11),
                       "without the column or the marker, a pre-retrieval copy recovers the token again"

          travel TokenSession::HANDOFF_TTL + 1.second do
            cache.clear
            assert_nil TokenSession.retrieve_once(late_copy, api_key_id: 11),
                       "the window closes when the handoff itself expires"
          end
          assert_nil ApiKeys::ApiKey.find(11).token_shown_at
        end
      end

      test "a cache that never remembers cannot reopen a durably claimed handoff" do
        cache = ActiveSupport::Cache::MemoryStore.new
        cache.stubs(:write).returns(true) # every marker "written", none kept
        cache.stubs(:exist?).returns(false)
        use_cache(cache)
        TokenSession.store(@session, bound_key("amnesiac_cache_token", 13))
        copies = Array.new(3) { @session.deep_dup }

        assert_equal "amnesiac_cache_token", TokenSession.retrieve_once(@session, api_key_id: 13)
        copies.each { |copy| assert_nil TokenSession.retrieve_once(copy, api_key_id: 13) }
      end

      test "the durable claim is made first and the cache marker still refuses a claim it did not see" do
        # A rolling deploy: a 0.5.1 process (no durable layer) released the
        # token and left only a cache marker; a 0.6.0 process then gets a copy.
        cache = ActiveSupport::Cache::MemoryStore.new
        use_cache(cache)
        TokenSession.store(@session, bound_key("rolling_deploy_token", 14))
        copied_cookie = @session.deep_dup
        ApiKeys::ApiKey.stubs(:claim_token_handoff!).returns(nil)
        assert_equal "rolling_deploy_token", TokenSession.retrieve_once(@session, api_key_id: 14)
        ApiKeys::ApiKey.unstub(:claim_token_handoff!)

        retrieval = TokenSession.retrieve_once_with_status(copied_cookie, api_key_id: 14)

        assert_nil retrieval.token
        assert_equal :already_shown, retrieval.status
        assert ApiKeys::ApiKey.find(14).token_shown?, "the claim ran before the marker refused"
      end

      test "a handoff whose key no longer exists is refused" do
        use_cache(ActiveSupport::Cache::MemoryStore.new)
        TokenSession.store(@session, bound_key("orphan_token", 15))
        ApiKeys::ApiKey.where(id: 15).delete_all

        retrieval = TokenSession.retrieve_once_with_status(@session, api_key_id: 15)

        assert_nil retrieval.token, "zero rows claimed fails closed"
        refute TokenSession.available?(@session, api_key_id: 15)
      end

      test "a database error during the claim withholds the token and logs no secret" do
        use_cache(ActiveSupport::Cache::MemoryStore.new)
        TokenSession.store(@session, bound_key("db_down_token", 16))
        ApiKeys::ApiKey.stubs(:claim_token_handoff!).raises(ActiveRecord::StatementInvalid, "db_down_token")
        warnings = []
        TokenSession.stubs(:log_warn).with { |message| warnings << message; true }

        retrieval = TokenSession.retrieve_once_with_status(@session, api_key_id: 16)

        assert_nil retrieval.token
        assert_equal :withheld, retrieval.status
        assert_equal ["[ApiKeys Security] Token handoff could not be recorded in the database " \
                      "(ActiveRecord::StatementInvalid); withholding the token."], warnings
      end

      test "available? fails closed when the database cannot be read" do
        use_cache(ActiveSupport::Cache::MemoryStore.new)
        TokenSession.store(@session, bound_key("db_unreadable_token", 17))
        ApiKeys::ApiKey.stubs(:token_handoff_claimable?).raises(ActiveRecord::StatementInvalid, "boom")
        TokenSession.stubs(:log_warn)

        refute TokenSession.available?(@session, api_key_id: 17)
        assert @session[:api_keys_new_token], "a failed check leaves the handoff in place"
      end

      test "the claim is the only writer of token_shown_at" do
        use_cache(ActiveSupport::Cache::NullStore.new)
        key = bound_key("readonly_token", 18)
        TokenSession.store(@session, key)
        copied_cookie = @session.deep_dup
        assert_equal "readonly_token", TokenSession.retrieve_once(@session, api_key_id: 18)
        record = ApiKeys::ApiKey.find(18)
        shown_at = record.token_shown_at
        assert shown_at

        # An ordinary save cannot clear it and reopen the handoff.
        begin
          record.update(token_shown_at: nil)
        rescue ActiveRecord::ActiveRecordError
          nil # raise_on_assign_to_attr_readonly refuses the assignment outright
        end
        assert_equal shown_at.to_i, record.reload.token_shown_at.to_i
        assert_nil TokenSession.retrieve_once(copied_cookie, api_key_id: 18)

        # Nor can the claim be repeated by calling it directly.
        refute ApiKeys::ApiKey.claim_token_handoff!(18)
      end

      test "retrieve_once_with_status says why no token came back" do
        use_cache(ActiveSupport::Cache::MemoryStore.new)
        assert_equal :missing, TokenSession.retrieve_once_with_status(@session, api_key_id: 20).status

        TokenSession.store(@session, bound_key("status_token", 20))
        copied_cookie = @session.deep_dup
        mismatched_copy = @session.deep_dup
        retrieved = TokenSession.retrieve_once_with_status(@session, api_key_id: 20)
        assert retrieved.retrieved?
        assert_equal "status_token", retrieved.token
        assert_predicate retrieved, :frozen?

        replay = TokenSession.retrieve_once_with_status(copied_cookie, api_key_id: 20)
        assert replay.already_shown?
        assert_nil replay.token

        # A handoff bound to another key says nothing about the requested one.
        assert_equal :missing, TokenSession.retrieve_once_with_status(mismatched_copy, api_key_id: 21).status
      end

      test "a retrieval result never prints its token" do
        require "pp"
        TokenSession.store(@session, bound_key("printable_secret_token", 40))
        retrieval = TokenSession.retrieve_once_with_status(@session, api_key_id: 40)
        assert_equal "printable_secret_token", retrieval.token, "the token is still readable on purpose"

        renderings = [retrieval.inspect, retrieval.to_s, "#{retrieval}", retrieval.pretty_inspect,
                      [retrieval].inspect, { result: retrieval }.inspect, retrieval.to_json, JSON.generate(retrieval.as_json)]
        renderings.each { |text| refute_includes text, "printable_secret_token" }
        assert_includes retrieval.inspect, "status=:retrieved"
        assert_includes retrieval.inspect, "token=[REDACTED]"
        assert_equal({ "status" => "retrieved", "token" => "[REDACTED]" }, JSON.parse(retrieval.to_json))

        missing = TokenSession.retrieve_once_with_status(@session, api_key_id: 40)
        assert_includes missing.inspect, "token=nil"
      end

      test "handoffs written before 0.5.1 are also one-time" do
        use_cache(ActiveSupport::Cache::MemoryStore.new)
        ensure_key_row(12)
        @session[:api_keys_new_token] = {
          "version" => TokenSession::HANDOFF_VERSION,
          "ciphertext" => @encryptor.encrypt_and_sign({ "token" => "pre_051_token", "api_key_id" => "12" },
                                                      expires_in: TokenSession::HANDOFF_TTL,
                                                      purpose: TokenSession::ENCRYPTION_PURPOSE),
          "api_key_id" => "12"
        }
        copied_cookie = @session.deep_dup

        assert_equal "pre_051_token", TokenSession.retrieve_once(@session, api_key_id: 12)
        assert_nil TokenSession.retrieve_once(copied_cookie, api_key_id: 12)
      end

      test "an authentic payload with a malformed handoff ID fails closed" do
        use_cache(ActiveSupport::Cache::MemoryStore.new)
        ensure_key_row(1)
        ["short", "../../escape-the-namespace-0123456789", 42, ""].each do |handoff_id|
          @session[:api_keys_new_token] = {
            "version" => TokenSession::HANDOFF_VERSION,
            "ciphertext" => @encryptor.encrypt_and_sign(
              { "token" => "odd_id_token", "api_key_id" => "1", "handoff_id" => handoff_id },
              expires_in: TokenSession::HANDOFF_TTL,
              purpose: TokenSession::ENCRYPTION_PURPOSE
            ),
            "api_key_id" => "1"
          }

          refute TokenSession.available?(@session, api_key_id: 1), handoff_id.inspect
          assert_nil TokenSession.retrieve_once(@session, api_key_id: 1), handoff_id.inspect
        end
        refute ApiKeys::ApiKey.find(1).token_shown?, "a payload that fails to decode claims nothing"
      end

      test "with NullStore the durable claim alone stops a copied session" do
        use_cache(ActiveSupport::Cache::NullStore.new)
        TokenSession.store(@session, bound_key("null_store_token", 2))
        copied_cookie = @session.deep_dup

        assert_equal "null_store_token", TokenSession.retrieve_once(@session, api_key_id: 2)
        assert_nil TokenSession.retrieve_once(@session, api_key_id: 2), "the same session is still one-time"
        assert_nil TokenSession.retrieve_once(copied_cookie, api_key_id: 2)
      end

      test "without the column, with NullStore the session deletion is the only protection" do
        TokenShownAtSchema.without_column do
          use_cache(ActiveSupport::Cache::NullStore.new)
          TokenSession.store(@session, bound_key("null_store_token", 2))
          copied_cookie = @session.deep_dup

          assert_equal "null_store_token", TokenSession.retrieve_once(@session, api_key_id: 2)
          assert_nil TokenSession.retrieve_once(@session, api_key_id: 2), "the same session is still one-time"
          # The 0.5.1 limitation: nothing durable and nothing cached, so a
          # copy taken before retrieval still carries the handoff.
          assert_equal "null_store_token", TokenSession.retrieve_once(copied_cookie, api_key_id: 2)
        end
      end

      test "without any Rails cache the session deletion and the durable claim protect the handoff" do
        use_cache(nil)
        TokenSession.store(@session, bound_key("no_cache_token", 2))
        copied_cookie = @session.deep_dup

        assert_equal "no_cache_token", TokenSession.retrieve_once(@session, api_key_id: 2)
        assert_nil TokenSession.retrieve_once(@session, api_key_id: 2)
        assert_nil TokenSession.retrieve_once(copied_cookie, api_key_id: 2)
      end

      test "a handoff that names no key keeps the cache marker as its only cross-copy layer" do
        cache = ActiveSupport::Cache::MemoryStore.new
        use_cache(cache)
        TokenSession.store(@session, "unbound_token")
        copied_cookie = @session.deep_dup
        late_copy = @session.deep_dup

        assert_equal "unbound_token", TokenSession.retrieve_once(@session)
        assert_nil TokenSession.retrieve_once(copied_cookie)
        cache.clear
        assert_equal "unbound_token", TokenSession.retrieve_once(late_copy),
                     "with no key row to claim, this is the documented 0.5.1 guarantee"
      end

      test "session token payloads are structurally bounded" do
        assert_raises(ArgumentError) do
          TokenSession.store(@session, "a" * (TokenSession::MAX_TOKEN_BYTESIZE + 1))
        end
        assert_raises(ArgumentError) { TokenSession.store(@session, "token\nvalue") }
        assert_empty @session

        @session[:api_keys_new_token] = {
          "token" => "a" * (TokenSession::MAX_TOKEN_BYTESIZE + 1),
          "api_key_id" => "1"
        }
        refute TokenSession.available?(@session, api_key_id: 1)
        assert_nil TokenSession.retrieve_once(@session, api_key_id: 1)
      end
    end
  end
end
