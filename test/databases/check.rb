# frozen_string_literal: true

# Runs every upgrade migration as the generators write them and as
# db:migrate runs them, with strong_migrations checking each one,
# and the row locks of ApiKeys::IdempotencyKey and
# ApiKeys::DeviceAuthorization, against a real database with real concurrent
# connections. The main suite runs on in-memory SQLite, which has one
# connection.
#
#   BUNDLE_GEMFILE=test/databases/Gemfile DB_ADAPTER=postgresql bundle exec ruby test/databases/check.rb
#
# DB_ADAPTER is postgresql, mysql2 or sqlite3. DB_HOST, DB_USERNAME and
# DB_PASSWORD name the server. UUID=1 makes every table use uuid keys.
ENV["RAILS_ENV"] = "test"
ENV["DATABASE_URL"] = "sqlite3::memory:" # replaced below; Rails needs one to boot

require "fileutils"
require "logger"
require "stringio"
require "tmpdir"
require "rails"
require "active_record/railtie"
# strong_migrations reads Rake.application when it refuses a migration, as
# under rails db:migrate.
require "rake"
require "strong_migrations"
require "api_keys"
require "rails/generators"
require "generators/api_keys/install_generator"
require "generators/api_keys/add_key_types_generator"
require "generators/api_keys/add_authentication_index_generator"
require "generators/api_keys/add_restrictions_generator"
require "generators/api_keys/add_key_activity_generator"
require "generators/api_keys/add_created_by_generator"
require "generators/api_keys/add_device_authorizations_generator"
require "generators/api_keys/add_idempotency_keys_generator"
require "minitest/autorun"

ADAPTER = ENV.fetch("DB_ADAPTER", "sqlite3")
DATABASE = "api_keys_database_check"

class DatabaseCheckApp < Rails::Application
  config.root = __dir__
  config.eager_load = false
  config.logger = Logger.new(nil)
  config.secret_key_base = "0" * 64
  config.generators { |generators| generators.orm :active_record, primary_key_type: :uuid } if ENV["UUID"].present?
end
Rails.application.initialize!

server = { host: ENV.fetch("DB_HOST", "127.0.0.1"), username: ENV["DB_USERNAME"].presence,
           password: ENV["DB_PASSWORD"].presence }.compact
CONFIG = case ADAPTER
         when "postgresql"
           ActiveRecord::Base.establish_connection(adapter: ADAPTER, database: "postgres", **server)
           ActiveRecord::Base.connection.execute("DROP DATABASE IF EXISTS #{DATABASE}")
           ActiveRecord::Base.connection.execute("CREATE DATABASE #{DATABASE}")
           { adapter: ADAPTER, database: DATABASE, pool: 10, **server }
         when "mysql2"
           ActiveRecord::Base.establish_connection(adapter: ADAPTER, **server)
           ActiveRecord::Base.connection.execute("DROP DATABASE IF EXISTS #{DATABASE}")
           ActiveRecord::Base.connection.execute("CREATE DATABASE #{DATABASE}")
           { adapter: ADAPTER, database: DATABASE, pool: 10, **server }
         else
           path = File.join(Dir.tmpdir, "#{DATABASE}.sqlite3")
           FileUtils.rm_f(Dir["#{path}*"])
           { adapter: ADAPTER, database: path, pool: 10, timeout: 1000 }
         end
ActiveRecord::Base.establish_connection(CONFIG)
ActiveRecord::Migration.verbose = false
# strong_migrations does not support SQLite, and says to skip it there.
# There the check shows that the migrations run, as on any database.
StrongMigrations.skip_database(:primary) if ADAPTER == "sqlite3"

# Writes each migration with its generator, as an app does.
MIGRATIONS = Dir.mktmpdir("api_keys_migrations")
[
  ApiKeys::Generators::InstallGenerator, ApiKeys::Generators::AddKeyTypesGenerator,
  ApiKeys::Generators::AddAuthenticationIndexGenerator, ApiKeys::Generators::AddRestrictionsGenerator,
  ApiKeys::Generators::AddKeyActivityGenerator, ApiKeys::Generators::AddCreatedByGenerator,
  ApiKeys::Generators::AddDeviceAuthorizationsGenerator, ApiKeys::Generators::AddIdempotencyKeysGenerator
].each do |generator|
  $stdout = StringIO.new
  generator.start([], destination_root: MIGRATIONS)
ensure
  $stdout = STDOUT
end

# Every upgrade migration, in the order db:migrate runs them.
UPGRADES = %w[add_key_types_to_api_keys add_authentication_index_to_api_keys add_restrictions_to_api_keys
              add_key_activity_to_api_keys add_created_by_to_api_keys create_api_keys_device_authorizations
              create_api_keys_idempotency_keys].freeze

# strong_migrations has no safe form of a check constraint on an existing
# MySQL table, so it refuses add_restrictions on MySQL. There the check runs
# it without strong_migrations, and test_a shows the refusal.
UNCHECKED = ADAPTER == "mysql2" ? %w[add_restrictions_to_api_keys] : []

def migration_file(name)
  Dir["#{MIGRATIONS}/db/migrate/*_#{name}.rb"].sole
end

# Runs one generated migration as db:migrate does: inside a DDL transaction
# unless the migration disables it, and checked by strong_migrations (which
# checks only the way up, by default). An unsafe migration raises.
def run_migration(name, direction, checked: !UNCHECKED.include?(name))
  file = migration_file(name)
  run = -> { ActiveRecord::MigrationContext.new(File.dirname(file)).run(direction, File.basename(file).to_i) }
  checked ? run.call : StrongMigrations::Checker.safety_assured(&run)
ensure
  [ApiKeys::ApiKey, ApiKeys::DeviceAuthorization, ApiKeys::IdempotencyKey].each(&:reset_column_information)
end

# Takes away what one upgrade adds, as an install from before it looks.
def strip_upgrade(name)
  connection = ActiveRecord::Base.connection
  case name
  when "add_key_types_to_api_keys"
    connection.remove_index(:api_keys, name: "index_api_keys_owner_type_env")
    %i[key_type environment].each do |column|
      connection.remove_index(:api_keys, column)
      connection.remove_column(:api_keys, column)
    end
  when "add_authentication_index_to_api_keys"
    connection.remove_index(:api_keys, name: "index_api_keys_authentication_lookup")
  when "add_restrictions_to_api_keys"
    connection.remove_check_constraint(:api_keys, name: "api_keys_restrictions_is_object")
    connection.remove_column(:api_keys, :restrictions)
  when "add_key_activity_to_api_keys"
    (ApiKeys::ApiKey::REFUSAL_STATS_COLUMNS + [ApiKeys::ApiKey::TOKEN_SHOWN_AT_COLUMN]).each do |column|
      connection.remove_column(:api_keys, column)
    end
  when "add_created_by_to_api_keys"
    connection.remove_reference(:api_keys, :created_by, polymorphic: true)
  end
end

def load_migration(name)
  source = File.read(migration_file(name))
  # The install migration gives JSON columns literal defaults, which MySQL
  # refuses. That migration is older than 0.7.0 and has an issue of its own;
  # here it only makes the api_keys table that the new migrations need.
  source = source.gsub(/default: (\[\]|\{\}), /, "") if name == "create_api_keys_table" && ADAPTER == "mysql2"
  Object.class_eval(source, name)
end

id_type = ENV["UUID"].present? ? :uuid : :primary_key
ActiveRecord::Schema.define { create_table(:users, id: id_type) { |t| t.string :name } }
load_migration("create_api_keys_table")
CreateApiKeysTable.migrate(:up)
# An install from before 0.3.0: the api_keys table without what the upgrades
# add. Then every upgrade, as an app runs them, on a table that has a row.
UPGRADES.each { |name| strip_upgrade(name) }
ActiveRecord::Base.connection.execute(<<~SQL)
  INSERT INTO api_keys (#{%w[prefix token_digest digest_algorithm last4 scopes metadata created_at updated_at].join(", ")})
  VALUES ('ak_old_', 'old-digest', 'sha256', 'old4', '[]', '{}', CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
SQL
UPGRADES.each { |name| run_migration(name, :up) }
OLD_KEY_RESTRICTIONS = ActiveRecord::Base.connection.select_value("SELECT restrictions FROM api_keys WHERE prefix = 'ak_old_'")
json = ADAPTER == "postgresql" ? :jsonb : :json
ApiKeys::ApiKey.attribute :scopes, json, default: []
ApiKeys::ApiKey.attribute :metadata, json, default: {}
ApiKeys::ApiKey.attribute :restrictions, json, default: {}

class User < ActiveRecord::Base
  has_api_keys
end

class DatabaseCheck < Minitest::Test
  Key = ApiKeys::IdempotencyKey

  def setup
    ApiKeys.reset_configuration!
    ApiKeys.configure do |config|
      config.enable_async_operations = false
      config.default_scopes = %w[read write]
    end
    ActiveRecord::Base.connection_pool.with_connection do
      Key.delete_all
      ApiKeys::DeviceAuthorization.delete_all
      ApiKeys::ApiKey.delete_all
      User.delete_all
    end
    @owner = User.create!(name: "Acme")
    @api_key = @owner.create_api_key!(name: "CI", created_by: @owner)
  end

  def self.test_order = :alpha

  def in_thread(&block)
    Thread.new { ActiveRecord::Base.connection_pool.with_connection(&block) }
  end

  def timed
    started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
    result = yield
    [result, Process.clock_gettime(Process::CLOCK_MONOTONIC) - started]
  end

  # Two migrations that strong_migrations refuses.
  MIGRATION_VERSION = ActiveRecord::VERSION::STRING.to_f

  class FourColumnIndex < ActiveRecord::Migration[MIGRATION_VERSION]
    def up = add_index(:api_keys, %i[name prefix last4 revoked_at])
  end

  # What the 0.7.0 add_created_by migration did: an index built inside the
  # migration's transaction.
  class IndexInsideTheTransaction < ActiveRecord::Migration[MIGRATION_VERSION]
    def up = add_reference(:api_keys, :reviewer, polymorphic: true, null: true)
  end

  def test_0_strong_migrations_checks_the_migrations_here
    skip "strong_migrations does not support SQLite" if ADAPTER == "sqlite3"

    error = assert_raises(StrongMigrations::UnsafeMigration) { FourColumnIndex.migrate(:up) }
    assert_match "more than three columns", error.message
    return unless ADAPTER == "postgresql"

    error = assert_raises(StrongMigrations::UnsafeMigration) { IndexInsideTheTransaction.migrate(:up) }
    assert_match "Adding an index non-concurrently", error.message
    ApiKeys::ApiKey.reset_column_information
    refute_includes ApiKeys::ApiKey.column_names, "reviewer_id", "strong_migrations stops before the statement"
  end

  def key_types_columns?
    (%w[key_type environment] - ApiKeys::ApiKey.column_names).empty?
  end

  def index_columns
    ActiveRecord::Base.connection.indexes(:api_keys).map(&:columns)
  end

  def restrictions_constraint
    connection = ActiveRecord::Base.connection
    return :unsupported unless connection.supports_check_constraints?

    connection.check_constraints(:api_keys).find { |constraint| constraint.name == "api_keys_restrictions_is_object" }
  end

  UPGRADE_INDEXES = [%w[key_type], %w[environment], %w[owner_type owner_id key_type environment],
                     %w[prefix last4 digest_algorithm], %w[created_by_type created_by_id]].freeze

  def assert_every_upgrade_is_in_place
    assert key_types_columns?
    assert ApiKeys::ApiKey.restrictions_column?
    assert ApiKeys::ApiKey.refusal_stats_columns?
    assert ApiKeys::ApiKey.token_shown_at_column?
    assert ApiKeys::ApiKey.created_by_columns?
    UPGRADE_INDEXES.each { |columns| assert_equal 1, index_columns.count(columns), columns.join(", ") }
    constraint = restrictions_constraint
    refute_nil constraint, "the restrictions constraint exists"
    assert constraint.validated?, "the restrictions constraint is validated" if ADAPTER == "postgresql"
    %i[api_keys_device_authorizations api_keys_idempotency_keys].each do |table|
      assert ActiveRecord::Base.connection.table_exists?(table), table
    end
  end

  def test_a_the_upgrade_migrations_run_up_down_and_up_again
    connection = ActiveRecord::Base.connection
    assert_every_upgrade_is_in_place
    assert_equal({}, JSON.parse(OLD_KEY_RESTRICTIONS), "a key from before the upgrade is unrestricted")
    Key.delete_all
    ApiKeys::DeviceAuthorization.delete_all
    ApiKeys::ApiKey.delete_all

    UPGRADES.reverse_each { |name| run_migration(name, :down) }
    refute key_types_columns?
    refute ApiKeys::ApiKey.restrictions_column?
    refute ApiKeys::ApiKey.refusal_stats_columns?
    refute ApiKeys::ApiKey.token_shown_at_column?
    refute ApiKeys::ApiKey.created_by_columns?
    assert_empty UPGRADE_INDEXES & index_columns
    %i[api_keys_device_authorizations api_keys_idempotency_keys].each { |table| refute connection.table_exists?(table) }

    if ADAPTER == "mysql2"
      error = assert_raises(StandardError) { run_migration("add_restrictions_to_api_keys", :up, checked: true) }
      assert_match "#strong_migrations", error.message
      refute ApiKeys::ApiKey.restrictions_column?, "strong_migrations stops before the statement"
    end
    UPGRADES.each { |name| run_migration(name, :up) }
    assert_every_upgrade_is_in_place

    # Idempotent: a second run, and a run that stopped half way, finish the
    # work and add nothing twice.
    [AddKeyTypesToApiKeys, AddAuthenticationIndexToApiKeys, AddKeyActivityToApiKeys, AddCreatedByToApiKeys]
      .each { |migration| migration.migrate(:up) }
    StrongMigrations::Checker.safety_assured { AddRestrictionsToApiKeys.migrate(:up) } # MySQL refuses it checked
    connection.remove_index(:api_keys, name: "index_api_keys_owner_type_env")
    AddKeyTypesToApiKeys.migrate(:up)
    connection.remove_index(:api_keys, name: "index_api_keys_on_created_by")
    AddCreatedByToApiKeys.migrate(:up)
    if ADAPTER == "postgresql" # the constraint was added, but not validated yet
      connection.remove_check_constraint(:api_keys, name: "api_keys_restrictions_is_object")
      connection.add_check_constraint(:api_keys, "jsonb_typeof(restrictions) = 'object'",
                                      name: "api_keys_restrictions_is_object", validate: false)
      refute restrictions_constraint.validated?, "precondition: not validated"
      AddRestrictionsToApiKeys.migrate(:up)
    end
    ApiKeys::ApiKey.reset_column_information
    assert_every_upgrade_is_in_place
  end

  def test_b_the_foreign_keys_match_the_key_types
    key_id = ApiKeys::ApiKey.columns_hash["id"]
    %w[api_keys_device_authorizations api_keys_idempotency_keys].each do |table|
      column = ActiveRecord::Base.connection.columns(table).find { |candidate| candidate.name == "api_key_id" }
      assert_equal key_id.sql_type, column.sql_type, table
    end
    created_by_uuid = ApiKeys::ApiKey.columns_hash["created_by_id"].sql_type.include?("uuid")
    assert_equal ENV["UUID"].present?, created_by_uuid
    assert_nil ApiKeys::DeviceAuthorization.columns_hash["scopes"].default
    assert_equal [], ApiKeys::DeviceAuthorization.new.scopes
  end

  def test_c_a_retry_of_a_short_write_replays_and_the_write_runs_once
    writes = Queue.new
    first = in_thread do
      Key.hold(@api_key, "short") do |record|
        writes << :first
        sleep 0.8
        record.answer!(201, @owner)
      end
    end
    sleep 0.3
    second = in_thread { Key.hold(@api_key, "short") { |record| record.answered? ? :replay : writes << :second } }

    assert_equal :replay, second.value
    first.join
    assert_equal 1, writes.size
  end

  def test_d_a_retry_of_a_long_write_answers_busy_after_the_timeout
    first = in_thread { Key.hold(@api_key, "long") { |record| sleep 4; record.answer!(201, @owner) } }
    sleep 0.3
    outcome, seconds = timed do
      in_thread do
        Key.hold(@api_key, "long") { :ran }
      rescue Key::Busy
        :busy
      end.value
    end
    first.join

    assert_equal :busy, outcome
    assert_operator seconds, :<, 3.5, "the retry waited #{seconds.round(1)} seconds"
    assert Key.find_by!(key: "long").answered?
  end

  def test_e_a_first_request_waits_at_most_the_timeout_for_another_insert_of_the_key
    inserted = Queue.new
    holder = in_thread do
      Key.transaction do
        Key.create!(api_key_id: @api_key.id, key: "racing")
        inserted << true
        sleep 4 # a claim that has not committed yet
      end
    end
    inserted.pop
    outcome, seconds = timed do
      in_thread do
        Key.hold(@api_key, "racing") { :ran }
      rescue Key::Busy
        :busy
      end.value
    end
    holder.join

    assert_equal :busy, outcome
    assert_operator seconds, :<, 3.5, "the claim waited #{seconds.round(1)} seconds"
  end

  def test_f_hold_refuses_to_run_inside_a_transaction_of_the_app
    error = assert_raises(ApiKeys::Error) { ActiveRecord::Base.transaction { Key.hold(@api_key, "nested") { :ran } } }

    assert_match "outside database transactions", error.message
  end

  def test_g_four_polls_at_once_of_one_approval_make_one_key
    authorization = ApiKeys::DeviceAuthorization.request!(client_id: "Fictional agent", scopes: %w[read])
    authorization.approve!(@owner, by: @owner)

    answers = 4.times.map do
      in_thread do
        poll = ApiKeys::DeviceAuthorization.find(authorization.id).poll!(client_id: "Fictional agent")
        poll.api_key ? :key : poll.error
      end
    end.map(&:value)

    assert_equal({ key: 1, "invalid_grant" => 3 }, answers.tally)
    assert_equal @owner, ApiKeys::ApiKey.find_by!(name: "Fictional agent").created_by
  end

  def test_h_the_lock_timeout_does_not_stay_on_the_connection
    Key.hold(@api_key, "settings") { |record| record.answer!(201, @owner) }

    connection = ActiveRecord::Base.connection
    case ADAPTER
    when "postgresql" then assert_equal "0", connection.select_value("SHOW lock_timeout")
    when "mysql2" then assert_equal 50, connection.select_value("SELECT @@SESSION.innodb_lock_wait_timeout").to_i
    else pass
    end
  end

  # A concurrent build that fails leaves an invalid index on PostgreSQL. The
  # next run of the migration removes it and builds it again. A unique build
  # over two equal rows fails in the same way as a lock timeout.
  def test_i_a_failed_concurrent_build_is_built_again_on_the_next_run
    skip "only PostgreSQL builds indexes concurrently" unless ADAPTER == "postgresql"

    connection = ActiveRecord::Base.connection
    now = Time.current
    twins = Array.new(2) do |index|
      { prefix: "ak_twin_", token_digest: "twin-#{index}", digest_algorithm: "sha256", last4: "twin",
        owner_type: "User", owner_id: @owner.id, created_by_type: "User", created_by_id: @owner.id,
        key_type: "secret", environment: "test", created_at: now, updated_at: now }
    end
    ApiKeys::ApiKey.insert_all!(twins)
    {
      AddCreatedByToApiKeys => ["index_api_keys_on_created_by", %w[created_by_type created_by_id]],
      AddKeyTypesToApiKeys => ["index_api_keys_owner_type_env", %w[owner_type owner_id key_type environment]],
      AddAuthenticationIndexToApiKeys => ["index_api_keys_authentication_lookup", %w[prefix last4 digest_algorithm]]
    }.each do |migration, (name, columns)|
      connection.remove_index(:api_keys, name: name, algorithm: :concurrently)
      assert_raises(ActiveRecord::RecordNotUnique) do
        connection.add_index(:api_keys, columns, name: name, unique: true, algorithm: :concurrently)
      end
      broken = connection.indexes(:api_keys).find { |index| index.name == name }
      refute broken.valid?, "precondition: #{name} is invalid"

      migration.migrate(:up)

      rebuilt = connection.indexes(:api_keys).find { |index| index.name == name }
      assert rebuilt.valid?, "#{migration}: #{name} is valid"
      refute rebuilt.unique, "#{migration}: #{name} is the migration's index"
      assert_equal columns, rebuilt.columns
    end
  end
end

Minitest.after_run do
  ActiveRecord::Base.connection_pool.disconnect!
  FileUtils.rm_rf(MIGRATIONS)
end
