# frozen_string_literal: true

require "test_helper"

module ApiKeys
  class PackagingTest < ApiKeys::Test
    EXCLUDED_DEVELOPMENT_FILES = %w[
      .simplecov
      AGENTS.md
      Appraisals
      CLAUDE.md
      Rakefile
      context7.json
      gemfiles/rails_7.2.gemfile
      gemfiles/rails_8.0.gemfile
      gemfiles/rails_8.1.gemfile
    ].freeze

    test "built gem metadata excludes development-only files" do
      specification = Gem::Specification.load(File.expand_path("../api_keys.gemspec", __dir__))

      EXCLUDED_DEVELOPMENT_FILES.each do |path|
        refute_includes specification.files, path
      end
      assert_includes specification.files, "lib/api_keys.rb"
      assert_includes specification.files, "app/controllers/api_keys/application_controller.rb"
      assert_includes specification.files, "README.md"
      assert_includes specification.files, "SECURITY.md"
    end
  end
end
