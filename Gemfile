# frozen_string_literal: true

source "https://rubygems.org"

# Load runtime dependencies from the gemspec
gemspec

# Rake is used by both development and test environments
gem "rake", "~> 13.0"

group :development do
  # Appraisal for testing against multiple Rails versions
  gem "appraisal"

  # Add development-only tools here (linting, profiling, etc.)
  # gem "rubocop", "~> 1.0"
  # gem "rubocop-rails"
  # gem "rubocop-performance"
  # gem "rubocop-rake"

  # Speed up boot time for the dummy app
  gem "bootsnap", require: false
end

group :test do
  # Testing framework and utilities
  gem "minitest", "~> 5.14"
  gem "minitest-reporters", "~> 1.4"
  gem "mocha", "~> 2.0"

  # Database for test dummy app
  gem "sqlite3", ">= 2.1"

  # Add test coverage, VCR, webmock, etc. as needed
  # gem "simplecov", require: false
  # gem "vcr"
  # gem "webmock"
end
