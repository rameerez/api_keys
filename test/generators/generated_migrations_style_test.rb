# frozen_string_literal: true

require "test_helper"
require "open3"
require "rbconfig"
require "stringio"
require "tmpdir"
require "rails/generators"
%w[install add_key_types add_authentication_index add_restrictions add_key_activity add_created_by
   add_device_authorizations add_idempotency_keys].each { |name| require "generators/api_keys/#{name}_generator" }

module ApiKeys
  module Generators
    # A host app on rubocop-rails-omakase (the Rails default) lints the
    # migrations the generators write into db/migrate, so each one must pass
    # as generated.
    class GeneratedMigrationsStyleTest < ActiveSupport::TestCase
      GENERATORS = [
        InstallGenerator, AddKeyTypesGenerator, AddAuthenticationIndexGenerator, AddRestrictionsGenerator,
        AddKeyActivityGenerator, AddCreatedByGenerator, AddDeviceAuthorizationsGenerator, AddIdempotencyKeysGenerator
      ].freeze

      test "every generated migration passes rubocop-rails-omakase" do
        Dir.mktmpdir("api_keys_style") do |dir|
          GENERATORS.each do |generator|
            $stdout = StringIO.new
            generator.start([], destination_root: dir)
          ensure
            $stdout = STDOUT
          end
          migrations = Dir["#{dir}/db/migrate/*.rb"].sort
          assert_equal GENERATORS.size, migrations.size

          config = File.join(dir, ".rubocop.yml")
          File.write(config, "inherit_gem: { rubocop-rails-omakase: rubocop.yml }\n")
          output, status = Open3.capture2e(RbConfig.ruby, Gem.bin_path("rubocop", "rubocop"), "--config", config,
                                           "--cache", "false", "--format", "simple", *migrations, chdir: dir)

          assert status.success?, output
          assert_match "#{migrations.size} files inspected, no offenses detected", output
        end
      end
    end
  end
end
