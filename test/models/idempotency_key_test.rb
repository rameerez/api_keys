# frozen_string_literal: true

require "test_helper"
require "rack/test"
require "tempfile"
require "rails/generators/test_case"
require "generators/api_keys/add_idempotency_keys_generator"

# The Idempotency-Key model (0.7.0): the claim, the lock, the answer and the
# request digest that ApiKeys::Idempotency and a host's own callers (an MCP
# tool, a job) share.
class IdempotencyKeyTest < ApiKeys::Test
  Key = ApiKeys::IdempotencyKey

  def setup
    super
    ApiKeys.configure { |config| config.enable_async_operations = false }
    @owner = User.create!(name: "Acme")
    @api_key = @owner.create_api_key!(name: "CI")
  end

  # == The request digest ==

  test "the digest stands for the parts and every parameter, with the names in any order" do
    digest = Key.digest_of("POST", "/widgets", { "name" => "Gear", "extra" => { "b" => 1, "a" => 2 } })

    assert_equal digest, Key.digest_of("POST", "/widgets", { extra: { a: 2, b: 1 }, name: "Gear" })
    refute_equal digest, Key.digest_of("PATCH", "/widgets", { "name" => "Gear", "extra" => { "b" => 1, "a" => 2 } })
    refute_equal digest, Key.digest_of("POST", "/widgets/1", { "name" => "Gear", "extra" => { "b" => 1, "a" => 2 } })
    refute_equal digest, Key.digest_of("POST", "/widgets", { "name" => "Gear" })
    refute_equal Key.digest_of("TOOL", { "ids" => [1, 2] }), Key.digest_of("TOOL", { "ids" => [2, 1] }), "a list keeps its order"
    assert_match(/\A\h{64}\z/, digest)
  end

  test "an upload stands in the digest by its bytes, its file name and its content type" do
    files = %w[first first second first].map do |content|
      Tempfile.new("upload").tap { |file| file.write(content) && file.flush }
    end
    upload = ->(index, type = "text/csv", name = "sales.csv") { Rack::Test::UploadedFile.new(files[index].path, type, original_filename: name) }
    digest = ->(value) { Key.digest_of("POST", { "file" => value }) }

    assert_equal digest.(upload.(0)), digest.(upload.(1)), "the same bytes, name and type"
    refute_equal digest.(upload.(0)), digest.(upload.(2)), "other bytes"
    refute_equal digest.(upload.(0)), digest.(upload.(3, "text/csv", "refunds.csv")), "another file name"
    refute_equal digest.(upload.(0)), digest.(upload.(3, "text/plain")), "another content type"
  ensure
    files&.each(&:close!)
  end

  test "an upload never encodes like an ordinary value" do
    file = Tempfile.new("upload").tap { |tempfile| tempfile.write("first") && tempfile.flush }
    upload = Rack::Test::UploadedFile.new(file.path, "text/csv", original_filename: "sales.csv")
    hex = Digest::SHA256.file(file.path).hexdigest
    digest = ->(value) { Key.digest_of("POST", { "file" => value }) }

    refute_equal digest.(upload), digest.(hex), "a text that holds the upload's digest"
    refute_equal digest.(upload), digest.(["upload", hex, "sales.csv", "text/csv"]), "a list that copies its encoding"
    refute_equal digest.({ "a" => "1" }), digest.([["a", "1"]]), "a hash and a list of pairs"
    refute_equal digest.("1"), digest.(1), "a text and a number"
  ensure
    file&.close!
  end

  # == Hold ==

  test "hold claims the key's row in a commit of its own and yields it locked" do
    yielded = nil
    Key.hold(@api_key, "widget-1") do |record|
      yielded = record
      assert record.persisted?
      assert_equal "widget-1", record.key
      assert_equal @api_key, record.api_key
      raise ActiveRecord::Rollback
    end

    assert_equal yielded, Key.sole, "the claim stays when the write rolls back"
    refute Key.sole.answered?
  end

  test "the write and its answer commit together, or neither does" do
    widget = User.create!(name: "Answered resource")
    Key.hold(@api_key, "widget-2") do |record|
      record.update!(request_digest: "a" * 64)
      record.answer!(201, widget)
    end
    record = Key.sole
    assert record.answered?
    assert_equal [201, widget, "a" * 64], [record.response_status, record.resource, record.request_digest]

    assert_raises(RuntimeError) do
      Key.hold(@api_key, "widget-3") do |held|
        User.create!(name: "Rolled back")
        held.answer!(201, widget)
        raise "a failure after the write"
      end
    end
    refute Key.find_by!(key: "widget-3").answered?
    assert_nil User.find_by(name: "Rolled back")
  end

  test "an answer names the record the write made or changed" do
    Key.hold(@api_key, "widget-4") do |record|
      assert_raises(ArgumentError) { record.answer!(201, nil) }
    end
  end

  test "hold yields the answered row to a retry, and a day-old key is claimed afresh" do
    widget = User.create!(name: "Answered resource")
    Key.hold(@api_key, "widget-5") { |record| record.answer!(200, widget) }

    Key.hold(@api_key, "widget-5") { |record| assert record.answered? }
    travel Key::RETENTION + 1.second do
      Key.hold(@api_key, "widget-5") { |record| refute record.answered? }
    end
    assert_equal 1, Key.count
  end

  test "each API key has its own keys" do
    other = @owner.create_api_key!(name: "Other")
    Key.hold(@api_key, "shared") { |record| record.answer!(200, @owner) }

    Key.hold(other, "shared") { |record| refute record.answered? }
    assert_equal 2, Key.where(key: "shared").count
  end

  test "a key is 1 to 255 characters" do
    assert_raises(ActiveRecord::RecordInvalid) { Key.hold(@api_key, "") { flunk } }
    assert_raises(ActiveRecord::RecordInvalid) { Key.hold(@api_key, "k" * 256) { flunk } }
    Key.hold(@api_key, "k" * 255) { |record| assert record.persisted? }
  end

  test "a lock wait that ends in a timeout is Busy, on every database" do
    timeouts = [
      ActiveRecord::LockWaitTimeout.new("PostgreSQL lock_timeout, MySQL innodb_lock_wait_timeout"),
      ActiveRecord::StatementTimeout.new("SQLite busy timeout, Rails 8"),
      sqlite_busy_before_rails_8
    ]

    timeouts.each do |timeout|
      Key.stubs(:waiting_at_most_lock_timeout).raises(timeout)
      assert_raises(Key::Busy, timeout.message) { Key.hold(@api_key, "busy") { flunk "the write must not run" } }
      Key.unstub(:waiting_at_most_lock_timeout)
    end
  end

  test "other database errors are not Busy" do
    Key.stubs(:waiting_at_most_lock_timeout).raises(ActiveRecord::StatementInvalid.new("syntax error"))

    assert_raises(ActiveRecord::StatementInvalid) { Key.hold(@api_key, "broken") { flunk } }
  end

  test "a row deleted between the claim and the lock is Busy, so the client retries" do
    Key.stubs(:create_or_find_by!).returns(nil)

    assert_raises(Key::Busy) { Key.hold(@api_key, "vanished") { flunk } }
  end

  test "the lock takes the database's write lock first on SQLite" do
    statements = []
    subscriber = ActiveSupport::Notifications.subscribe("sql.active_record") { |*, payload| statements << payload[:sql] }
    Key.hold(@api_key, "locked") { |record| assert record }
    ActiveSupport::Notifications.unsubscribe(subscriber)

    locking = statements.grep(/api_keys_idempotency_keys/).drop_while { |sql| !sql.start_with?("UPDATE") }
    assert_match(/\AUPDATE "api_keys_idempotency_keys" SET "updated_at"/, locking.first)
    assert_match(/\ASELECT "api_keys_idempotency_keys"\.\* FROM/, locking.second)
  end

  test "hold refuses to run inside a transaction of the app, where its claim could not commit on its own" do
    error = assert_raises(ApiKeys::Error) do
      ActiveRecord::Base.transaction { Key.hold(@api_key, "nested") { flunk "the write must not run" } }
    end

    assert_match "outside database transactions", error.message
    assert_empty Key.all
  end

  test "hold refuses a transaction that nothing can join too: an outer rollback would remove the claim" do
    connection = ActiveRecord::Base.connection
    connection.begin_transaction(joinable: false)

    assert_raises(ApiKeys::Error) { Key.hold(@api_key, "production-wrapper") { flunk "the write must not run" } }
  ensure
    connection.rollback_transaction if connection.transaction_open?
  end

  test "transactional tests opt in with the test-only switch" do
    ApiKeys.configuration.idempotency_in_test_transactions = true
    connection = ActiveRecord::Base.connection
    connection.begin_transaction(joinable: false) # what Rails opens around a transactional test
    Key.hold(@api_key, "in-a-test") { |record| record.answer!(201, @owner) }

    assert Key.find_by!(key: "in-a-test").answered?
  ensure
    connection.rollback_transaction if connection.transaction_open?
  end

  test "the test-only switch is off by default, takes only true or false, and refuses production" do
    refute ApiKeys::Configuration.new.idempotency_in_test_transactions
    assert_raises(ArgumentError) { ApiKeys.configuration.idempotency_in_test_transactions = "yes" }

    Rails.stubs(:env).returns(ActiveSupport::EnvironmentInquirer.new("production"))
    error = assert_raises(ArgumentError) { ApiKeys.configuration.idempotency_in_test_transactions = true }
    assert_match "tests only", error.message
    ApiKeys.configuration.idempotency_in_test_transactions = false
  end

  test "the digest of an overlapping query and body differs from the same names moved" do
    once = Key.digest_of("POST", "/widgets", { "query" => { "name" => "A" }, "body" => { "name" => "body" } })
    moved = Key.digest_of("POST", "/widgets", { "query" => { "name" => "B" }, "body" => { "name" => "body" } })
    nested = Key.digest_of("POST", "/w", { "query" => {}, "body" => { "a" => { "y" => 1, "x" => [{ "q" => 1, "p" => 2 }] } } })
    reordered = Key.digest_of("POST", "/w", { "body" => { "a" => { "x" => [{ "p" => 2, "q" => 1 }], "y" => 1 } }, "query" => {} })

    refute_equal once, moved
    assert_equal nested, reordered
  end

  # == Housekeeping ==

  test "prune! deletes the keys older than a day" do
    Key.hold(@api_key, "old") { |record| record }
    travel Key::RETENTION + 1.second do
      Key.hold(@api_key, "recent") { |record| record }
      assert_equal 1, Key.prune!
    end
    assert_equal ["recent"], Key.pluck(:key)
  end

  test "a deleted API key takes its keys with it" do
    Key.hold(@api_key, "gone") { |record| record }

    ApiKeys::ApiKey.where(id: @api_key.id).delete_all

    assert_empty Key.all
  end

  private

  # Rails 7.2 raises SQLite's "database is locked" as a plain StatementInvalid.
  def sqlite_busy_before_rails_8
    raise SQLite3::BusyException, "database is locked"
  rescue SQLite3::BusyException
    begin
      raise ActiveRecord::StatementInvalid, "SQLite3::BusyException: database is locked"
    rescue ActiveRecord::StatementInvalid => error
      error
    end
  end

  class AddIdempotencyKeysGeneratorTest < Rails::Generators::TestCase
    tests ApiKeys::Generators::AddIdempotencyKeysGenerator
    destination File.expand_path("../../tmp/add_idempotency_keys_generator", __dir__)
    setup :prepare_destination
    setup { ApiKeys.reset_configuration! } # other suites configure key types

    FILE = "db/migrate/create_api_keys_idempotency_keys.rb"

    test "generates the table, which keeps no response body" do
      run_generator

      assert_migration FILE do |migration|
        assert_includes migration, "class CreateApiKeysIdempotencyKeys < ActiveRecord::Migration["
        assert_includes migration, "create_table :api_keys_idempotency_keys"
        assert_includes migration, "foreign_key: { on_delete: :cascade }"
        assert_includes migration, "t.index [:api_key_id, :key], unique: true"
        refute_match(/:body|:response_body/, migration)
        refute_includes migration, "def migration_version"
      end
    end

    test "the generated migration really creates and drops the table the model uses" do
      run_generator
      load migration_file_name(FILE)
      connection = ActiveRecord::Base.connection
      connection.drop_table(:api_keys_idempotency_keys)

      ActiveRecord::Migration.suppress_messages { ::CreateApiKeysIdempotencyKeys.migrate(:up) }
      ApiKeys::IdempotencyKey.reset_column_information
      assert_equal %w[api_keys], connection.foreign_keys(:api_keys_idempotency_keys).map(&:to_table)
      assert connection.index_exists?(:api_keys_idempotency_keys, %i[api_key_id key], unique: true)

      owner = ::User.create!(name: "Migrated owner")
      api_key = owner.create_api_key!(name: "CI")
      ApiKeys::IdempotencyKey.hold(api_key, "migrated") { |record| record.answer!(201, owner) }
      assert ApiKeys::IdempotencyKey.sole.answered?

      ApiKeys::IdempotencyKey.delete_all
      ActiveRecord::Migration.suppress_messages { ::CreateApiKeysIdempotencyKeys.migrate(:down) }
      refute connection.table_exists?(:api_keys_idempotency_keys)
    ensure
      unless ActiveRecord::Base.connection.table_exists?(:api_keys_idempotency_keys)
        ActiveRecord::Migration.suppress_messages { ::CreateApiKeysIdempotencyKeys.migrate(:up) }
      end
      ApiKeys::IdempotencyKey.reset_column_information
      ::User.delete_all
      ApiKeys::ApiKey.delete_all
      Object.send(:remove_const, :CreateApiKeysIdempotencyKeys) if Object.const_defined?(:CreateApiKeysIdempotencyKeys)
    end
  end
end
