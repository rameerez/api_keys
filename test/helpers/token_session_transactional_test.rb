# frozen_string_literal: true

require "test_helper"
require "active_record/fixtures"
require "tmpdir"

module ApiKeys
  module Helpers
    # The one-time token handoff in a host app's tests. From 0.6.0 to 0.8.0 a
    # retrieval inside any open transaction was refused, and a transactional
    # test is always inside one, so a test that created a key and read its
    # token got nil. Since 0.8.1 the test's own transaction does not count.
    class TokenSessionInTransactionalTestsTest < ApiKeys::Test
      include ActiveRecord::TestFixtures
      self.use_transactional_tests = true

      def setup
        super
        # No cache marker: only the durable claim decides.
        Rails.stubs(:cache).returns(ActiveSupport::Cache::NullStore.new)
        TokenSession.stubs(:log_warn)
        @key = User.create!(name: "Transactional owner").create_api_key!(name: "Transactional key")
        @token = @key.token # reload forgets it
        @session = {}
        TokenSession.store(@session, @key)
        @copied_cookie = @session.deep_dup
      end

      def assert_only_the_test_transaction_is_open
        ApiKeys::ApiKey.connection_pool.with_connection do |connection|
          assert_equal 1, connection.open_transactions, "precondition: the test's transaction is open"
          refute connection.current_transaction.joinable?, "precondition: it is the test's non-joinable transaction"
        end
      end

      test "the first retrieval returns the token and the second does not, as in production" do
        assert_only_the_test_transaction_is_open

        first = TokenSession.retrieve_once_with_status(@session, api_key: @key)
        replay = TokenSession.retrieve_once_with_status(@copied_cookie, api_key: @key)
        refresh = TokenSession.retrieve_once_with_status(@session, api_key: @key)

        assert_equal :retrieved, first.status
        assert_equal @token, first.token
        assert @key.reload.token_shown?, "the claim is recorded in the test's transaction"
        assert_equal :already_shown, replay.status, "a copied session gets nothing"
        assert_nil replay.token
        assert_equal :missing, refresh.status, "a refresh gets nothing"
        assert_nil refresh.token
      end

      test "retrieve_once returns the token once" do
        assert_equal @token, TokenSession.retrieve_once(@session, api_key: @key)
        assert_nil TokenSession.retrieve_once(@copied_cookie, api_key: @key)
      end

      test "a transaction opened on top of the test's transaction still refuses the retrieval" do
        {
          "ApiKey.transaction" => ->(&work) { ApiKeys::ApiKey.transaction(&work) },
          "a host model's transaction" => ->(&work) { User.transaction(&work) },
          "a savepoint (requires_new)" => ->(&work) { ApiKeys::ApiKey.transaction(requires_new: true, &work) },
          "a non-joinable transaction" => ->(&work) { ApiKeys::ApiKey.transaction(joinable: false, &work) }
        }.each do |label, wrap|
          retrieval = nil
          wrap.call { retrieval = TokenSession.retrieve_once_with_status(@session, api_key: @key) }

          assert_equal :inside_transaction, retrieval.status, label
          assert_nil retrieval.token, label
          refute @key.reload.token_shown?, "#{label}: nothing is recorded"
        end

        assert_equal @token, TokenSession.retrieve_once(@session, api_key: @key), "the handoff was kept"
        assert_nil TokenSession.retrieve_once(@copied_cookie, api_key: @key)
      end

      test "outside the test environment the same transaction refuses the retrieval" do
        Rails.stubs(:env).returns(ActiveSupport::EnvironmentInquirer.new("production"))

        retrieval = TokenSession.retrieve_once_with_status(@session, api_key: @key)

        assert_equal :inside_transaction, retrieval.status
        assert_nil retrieval.token
        refute @key.reload.token_shown?
      end
    end

    # The same handoff with real commits: no transaction is open, so the claim
    # commits on its own before the token is returned. Another connection
    # sees it, and a copy of the session gets nothing.
    class TokenSessionWithRealCommitsTest < ApiKeys::Test
      include ActiveRecord::TestFixtures
      self.use_transactional_tests = false

      def setup
        super
        Rails.stubs(:cache).returns(ActiveSupport::Cache::NullStore.new)
      end

      # Points ApiKeys::ApiKey at a file-backed SQLite database for the block,
      # so a second connection reads what the first one committed. (The
      # shared in-memory test database is private to one connection.)
      def with_file_database
        Dir.mktmpdir("api_keys_commit") do |dir|
          ApiKeys::ApiKey.establish_connection(adapter: "sqlite3", database: File.join(dir, "commit.sqlite3"), pool: 4)
          ApiKeys::ApiKey.connection_pool.with_connection do |connection|
            connection.create_table :api_keys do |t|
              t.string :prefix, null: false
              t.string :token_digest, null: false
              t.string :digest_algorithm, null: false
              t.string :name
              t.references :owner, polymorphic: true, null: true
              t.references :created_by, polymorphic: true, null: true
              t.text :scopes, default: "[]", null: false
              t.text :metadata, default: "{}", null: false
              t.text :restrictions, default: "{}", null: false
              t.datetime :expires_at
              t.datetime :last_used_at
              t.bigint :requests_count, default: 0, null: false
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

      test "the claim commits before the token is returned, and a copy of the session gets nothing" do
        with_file_database do
          key = User.create!(name: "Committing owner").create_api_key!(name: "Committed key")
          session = {}
          TokenSession.store(session, key)
          copied_cookie = session.deep_dup
          retrieval = shown_at = nil

          # This thread keeps its connection, so the reader gets another one.
          ApiKeys::ApiKey.connection_pool.with_connection do |retriever|
            refute retriever.transaction_open?, "precondition: no transaction is open"
            retrieval = TokenSession.retrieve_once_with_status(session, api_key: key)
            shown_at = Thread.new do
              ApiKeys::ApiKey.connection_pool.with_connection do |reader|
                refute_equal retriever, reader, "precondition: the claim is read on another connection"
                reader.select_value("SELECT token_shown_at FROM api_keys WHERE id = #{Integer(key.id)}")
              end
            end.value
          end

          assert_equal :retrieved, retrieval.status
          assert_equal key.token, retrieval.token
          assert shown_at, "the claim is committed: another connection sees it"
          assert_nil TokenSession.retrieve_once(copied_cookie, api_key: key)
        end
      end
    end
  end
end
