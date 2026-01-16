# frozen_string_literal: true

source "https://rubygems.org"

# Load runtime dependencies from the gemspec
gemspec

# Rake is used by both development and test environments
gem "rake", "~> 13.0"

group :development, :test do
  gem "appraisal"
  gem "minitest", "~> 6.0"
  gem "minitest-mock"
  gem "minitest-reporters"
  gem "rack-test"
  gem "simplecov", require: false
  gem "sqlite3", ">= 2.1"

  # Speed up boot time for the dummy app
  gem "bootsnap", require: false

  gem "mocha", "~> 2.0"

  # Ruby 4.0+ compatibility: ostruct removed from stdlib
  gem "ostruct"
end
