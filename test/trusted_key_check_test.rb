# frozen_string_literal: true

require "test_helper"
require "active_job"
require "set"
require "rails/generators/test_case"
require "generators/api_keys/add_created_by_generator"
require "generators/api_keys/install_generator"

# The person behind a key (0.7.0): `created_by` names who made a key whose
# owner is not a person, and `config.trusted_key_check` refuses the key once
# that person no longer stands behind it, with 403 `untrusted_key`.
class TrustedKeyCheckTest < ApiKeys::Test
  include ActiveJob::TestHelper

  class FakeRequest
    attr_reader :headers, :query_parameters, :protocol, :uuid, :remote_ip

    def initialize(token)
      @headers = { "Authorization" => "Bearer #{token}" }
      @query_parameters = {}
      @protocol = "https://"
      @remote_ip = "203.0.113.7"
      @uuid = SecureRandom.uuid
    end
  end

  class FakeController
    include ApiKeys::Authentication

    attr_reader :rendered, :request

    def initialize(request)
      @request = request
      @rendered = nil
    end

    def render(json:, status:)
      @rendered = { json: json, status: status }
    end
  end

  # A host that renders the gem's refusals in its own error shape.
  class HostShapedController < FakeController
    def render_unauthorized(error_code:, message:, status: :unauthorized, required_scope: nil)
      render json: { code: error_code.to_s, message: message }, status: status
    end
  end

  def setup
    super
    ApiKeys.configure do |config|
      config.enable_async_operations = true
      config.track_requests_count = true
    end
    @organization = User.create!(name: "Acme") # stands in for an organization
    @person = User.create!(name: "Ada")
    @managers = Set[@person.id]
  end

  def trust_managers!
    managers = @managers
    ApiKeys.configuration.trusted_key_check = ->(api_key) { managers.include?(api_key.created_by_id) }
  end

  def authenticate(key, controller_class: FakeController, **options)
    controller = controller_class.new(FakeRequest.new(key.token))
    controller.send(:authenticate_api_key!, **options)
    controller
  end

  # == created_by ==

  test "create_api_key! names the person behind the key" do
    key = @organization.create_api_key!(name: "CI", created_by: @person)

    assert_equal @person, key.created_by
    assert_equal @person, ApiKeys::ApiKey.find(key.id).created_by
    assert_equal ["User", @person.id], ApiKeys::ApiKey.where(id: key.id).pick(:created_by_type, :created_by_id)
  end

  test "created_by is optional" do
    assert_nil @organization.create_api_key!(name: "CI").created_by
  end

  test "no update can name another person behind a key" do
    key = @organization.create_api_key!(name: "CI", created_by: @person)
    other = User.create!(name: "Mallory")

    refute key.update(created_by: other)
    assert_includes key.errors[:created_by_id], "cannot be changed after creation"
    assert_equal @person, key.reload.created_by

    unnamed = @organization.create_api_key!(name: "Old")
    refute unnamed.update(created_by: other), "a key made without a person cannot gain one either"
    assert_nil unnamed.reload.created_by
    assert unnamed.update(name: "Renamed"), "other edits still save"
  end

  test "the bypass paths cannot change the person behind a key either" do
    key = @organization.create_api_key!(name: "CI", created_by: @person)
    other = User.create!(name: "Mallory")

    assert_raises(ActiveRecord::ActiveRecordError) { key.update_column(:created_by_id, other.id) }
    assert_raises(ActiveRecord::ActiveRecordError) { key.update_columns(created_by_type: "User", created_by_id: other.id) }
    key.reload.created_by = other
    key.save!(validate: false)
    assert_equal @person, ApiKeys::ApiKey.find(key.id).created_by, "a save without validations leaves the columns alone"
  end

  test "a backfill of keys made before the columns existed writes them with SQL" do
    unnamed = @organization.create_api_key!(name: "Old")

    ApiKeys::ApiKey.where(id: unnamed.id, created_by_id: nil).update_all(created_by_type: "User", created_by_id: @person.id)

    assert_equal @person, unnamed.reload.created_by
  end

  test "without the created_by columns keys work, and naming a person asks for the migration" do
    CreatedBySchema.without_columns do
      refute ApiKeys::ApiKey.created_by_columns?

      key = @organization.create_api_key!(name: "CI")
      assert key.persisted?
      assert_nil key.created_by
      assert authenticate(key).send(:current_api_key)
      assert key.update(name: "Renamed"), "the immutable created_by needs no column to save"

      error = assert_raises(ApiKeys::Errors::CreatedByMigrationRequiredError) do
        @organization.create_api_key!(name: "CI", created_by: @person)
      end
      assert_match "rails generate api_keys:add_created_by", error.message
    end
    assert ApiKeys::ApiKey.created_by_columns?
  end

  # == trusted_key_check ==

  test "without a check every valid key is trusted, as before" do
    controller = authenticate(@organization.create_api_key!(name: "CI"))

    assert_nil controller.rendered
    assert controller.send(:current_api_key)
  end

  test "a key works while its person stands behind it, and stops when that person leaves" do
    trust_managers!
    key = @organization.create_api_key!(name: "CI", created_by: @person)

    working = authenticate(key)
    assert_nil working.rendered
    assert_equal key, working.send(:current_api_key)

    @managers.delete(@person.id) # the person left, or no longer manages the organization
    refused = authenticate(key)
    assert_equal :forbidden, refused.rendered[:status]
    assert_equal :untrusted_key, refused.rendered[:json][:error]
    assert_match "no longer trusted", refused.rendered[:json][:message]
    assert_nil refused.send(:current_api_key), "an untrusted key must not remain in controller state"
    assert_nil refused.send(:current_api_owner)
  end

  test "a key without a person is refused when the check needs one" do
    trust_managers!

    assert_equal :untrusted_key, authenticate(@organization.create_api_key!(name: "Old")).rendered[:json][:error]
  end

  test "the check gets the authenticated key, and any truthy answer trusts it" do
    seen = []
    ApiKeys.configuration.trusted_key_check = ->(api_key) { seen << api_key; "yes" }
    key = @organization.create_api_key!(name: "CI")

    assert_nil authenticate(key).rendered
    assert_equal [key], seen
  end

  test "the check runs after the scope check: a key without the scope is refused for its scope" do
    calls = 0
    ApiKeys.configuration.trusted_key_check = ->(_api_key) { calls += 1; false }
    key = @organization.create_api_key!(name: "CI", scopes: %w[read])

    assert_equal :missing_scope, authenticate(key, scope: "write").rendered[:json][:error]
    assert_equal 0, calls
    assert_equal :untrusted_key, authenticate(key, scope: "read").rendered[:json][:error]
    assert_equal 1, calls
  end

  test "an error in the check fails the request; it never passes as trusted" do
    ApiKeys.configuration.trusted_key_check = ->(_api_key) { raise ActiveRecord::ConnectionNotEstablished }
    controller = FakeController.new(FakeRequest.new(@organization.create_api_key!(name: "CI").token))

    assert_raises(ActiveRecord::ConnectionNotEstablished) { controller.send(:authenticate_api_key!) }
    assert_nil controller.rendered
  end

  test "an untrusted key renders through render_unauthorized, so a host's own error shape applies" do
    ApiKeys.configuration.trusted_key_check = ->(_api_key) { false }
    controller = authenticate(@organization.create_api_key!(name: "CI"), controller_class: HostShapedController)

    assert_equal({ code: "untrusted_key", message: "API key is no longer trusted: the person behind it no longer stands behind it" },
                 controller.rendered[:json])
    assert_equal :forbidden, controller.rendered[:status]
  end

  test "the refusal message can be changed with I18n" do
    I18n.backend.store_translations(:en, api_keys: { errors: { untrusted_key: "Ask an admin for a new key." } })
    ApiKeys.configuration.trusted_key_check = ->(_api_key) { false }

    assert_equal "Ask an admin for a new key.", authenticate(@organization.create_api_key!(name: "CI")).rendered[:json][:message]
  ensure
    I18n.reload!
  end

  test "an untrusted request is a refusal of the key: stamped as one, never as a use" do
    ApiKeys.configuration.trusted_key_check = ->(_api_key) { false }
    ApiKeys.configuration.after_authentication = ->(context) { context }
    key = @organization.create_api_key!(name: "CI")

    authenticate(key)

    stats = enqueued_jobs.select { |job| job[:job] == ApiKeys::Jobs::UpdateStatsJob }
    assert_equal 1, stats.length
    assert_equal({ refusal_code: "untrusted_key" }, ActiveJob::Arguments.deserialize(stats.sole[:args]).last)
    after = enqueued_jobs.map { |job| ActiveJob::Arguments.deserialize(job[:args]) }.find { |args| args.first == :after_authentication }
    assert_equal({ success: false, error_code: :untrusted_key, api_key_id: key.id }, after.last.slice(:success, :error_code, :api_key_id))

    perform_enqueued_jobs
    key.reload
    assert_equal "untrusted_key", key.last_refusal_code
    assert_nil key.last_used_at
    assert_equal "the person behind the key no longer stands behind it",
                 Class.new { include ApiKeys::ViewHelpers }.new.api_key_refusal_reason(key)
  end

  test "trusted_key_check must be callable or nil" do
    assert_raises(ArgumentError) { ApiKeys.configuration.trusted_key_check = "managed_by?" }
    assert_raises(ArgumentError) { ApiKeys.configuration.trusted_key_check = false }
    ApiKeys.configuration.trusted_key_check = nil
    assert_nil ApiKeys.configuration.trusted_key_check
    assert_nil ApiKeys::Configuration.new.trusted_key_check
  end

  # == The device flow names the person who approved ==

  test "a key made by the device flow names the person who approved it" do
    ApiKeys.configuration.default_scopes = %w[read]
    authorization = ApiKeys::DeviceAuthorization.request!(client_id: "Fictional agent", scopes: %w[read])
    authorization.approve!(@organization, by: @person)

    key = authorization.poll!(client_id: "Fictional agent").api_key
    assert_equal @person, ApiKeys::ApiKey.find(key.id).created_by

    trust_managers!
    assert_nil authenticate(key).rendered
    @managers.clear
    assert_equal :untrusted_key, authenticate(key).rendered[:json][:error]
  end

  test "without the created_by columns the device flow still makes the key" do
    ApiKeys.configuration.default_scopes = %w[read]
    CreatedBySchema.without_columns do
      authorization = ApiKeys::DeviceAuthorization.request!(client_id: "Fictional agent", scopes: %w[read])
      authorization.approve!(@organization, by: @person)

      assert authorization.poll!(client_id: "Fictional agent").api_key.persisted?
      assert_equal @person, authorization.reload.decided_by, "the person is on the request"
    end
  end

  # == Generators ==

  class AddCreatedByGeneratorTest < Rails::Generators::TestCase
    tests ApiKeys::Generators::AddCreatedByGenerator
    destination File.expand_path("../tmp/add_created_by_generator", __dir__)
    setup :prepare_destination

    # test/databases/check.rb runs this migration as db:migrate does on
    # PostgreSQL, MySQL and SQLite, with strong_migrations.
    test "generates one idempotent migration that strong_migrations accepts on PostgreSQL" do
      run_generator

      assert_migration "db/migrate/add_created_by_to_api_keys.rb" do |migration|
        assert_includes migration, "class AddCreatedByToApiKeys < ActiveRecord::Migration["
        assert_includes migration, "disable_ddl_transaction!"
        assert_includes migration, "unless column_exists?(:api_keys, :created_by_id)"
        assert_includes migration, "add_reference :api_keys, :created_by, polymorphic: true, null: true, " \
                                   "type: foreign_key_type, index: false"
        assert_includes migration, "return if index_exists?(:api_keys, INDEX_COLUMNS)"
        assert_includes migration, 'INDEX_NAME = "index_api_keys_on_created_by"'
        assert_includes migration, "{ algorithm: :concurrently }"
        refute_includes migration, "def migration_version"
      end
    end

    test "the index is built concurrently on PostgreSQL and PostGIS, and as usual elsewhere" do
      run_generator
      load migration_file_name("db/migrate/add_created_by_to_api_keys.rb")
      migration = ::AddCreatedByToApiKeys.new

      { "PostgreSQL" => { algorithm: :concurrently }, "PostGIS" => { algorithm: :concurrently },
        "Mysql2" => {}, "Trilogy" => {}, "SQLite" => {} }.each do |adapter, options|
        migration.stubs(:connection).returns(stub(adapter_name: adapter))

        assert_equal options, migration.send(:index_algorithm), adapter
      end
    ensure
      Object.send(:remove_const, :AddCreatedByToApiKeys) if Object.const_defined?(:AddCreatedByToApiKeys)
    end

    test "the generated migration really adds, re-runs and removes the columns and the index" do
      run_generator
      load migration_file_name("db/migrate/add_created_by_to_api_keys.rb")
      migration = ::AddCreatedByToApiKeys.new

      CreatedBySchema.without_columns do
        ActiveRecord::Migration.suppress_messages do
          migration.migrate(:up)
          migration.migrate(:up) # idempotent: a second run is a no-op
        end
        ApiKeys::ApiKey.reset_column_information
        assert ApiKeys::ApiKey.created_by_columns?
        assert ApiKeys::ApiKey.columns_hash["created_by_id"].null, "existing keys keep NULL"
        assert ActiveRecord::Base.connection.index_exists?(:api_keys, %i[created_by_type created_by_id],
                                                           name: "index_api_keys_on_created_by")

        # A run that stopped after the columns builds the index on the next run.
        ActiveRecord::Base.connection.remove_index(:api_keys, name: "index_api_keys_on_created_by")
        ActiveRecord::Migration.suppress_messages { migration.migrate(:up) }
        assert ActiveRecord::Base.connection.index_exists?(:api_keys, %i[created_by_type created_by_id])

        ActiveRecord::Migration.suppress_messages { migration.migrate(:down) }
        ApiKeys::ApiKey.reset_column_information
        refute ApiKeys::ApiKey.created_by_columns?
      end
      assert ApiKeys::ApiKey.created_by_columns?, "the shared test schema is restored"
    ensure
      Object.send(:remove_const, :AddCreatedByToApiKeys) if Object.const_defined?(:AddCreatedByToApiKeys)
    end
  end

  class InstallGeneratorCreatedByTest < Rails::Generators::TestCase
    tests ApiKeys::Generators::InstallGenerator
    destination File.expand_path("../tmp/install_generator_created_by", __dir__)
    setup :prepare_destination

    test "new installs get created_by from the start" do
      run_generator

      assert_migration "db/migrate/create_api_keys_table.rb" do |migration|
        assert_includes migration, "t.references :created_by, polymorphic: true, null: true, type: foreign_key_type"
      end
    end
  end
end
