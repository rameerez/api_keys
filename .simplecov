# frozen_string_literal: true

# SimpleCov configuration file (auto-loaded before test suite).
# Starting coverage and reporting live in test_helper.rb so this file remains
# configuration-only, as required by current SimpleCov versions.

SimpleCov.configure do
  # Use SimpleFormatter for terminal-only output (no HTML generation)
  formatter SimpleCov::Formatter::SimpleFormatter

  # Track coverage for the lib directory (gem source code)
  skip "/test/"

  # Track the lib and app directories
  cover "{lib,app}/**/*.rb"

  # Enable branch coverage for more detailed metrics
  enable_coverage :branch

  # Enforce the hardened baseline so security-path coverage cannot regress.
  minimum_coverage line: 80, branch: 75

  # Disambiguate parallel test runs
  command_name "Job #{ENV['TEST_ENV_NUMBER']}" if ENV['TEST_ENV_NUMBER']
end
