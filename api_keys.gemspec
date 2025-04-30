# frozen_string_literal: true

require_relative "lib/api_keys/version"

Gem::Specification.new do |spec|
  spec.name = "api_keys"
  spec.version = ApiKeys::VERSION
  spec.authors = ["rameerez"]
  spec.email = ["rubygems@rameerez.com"]

  spec.summary     = "Gate your Rails API with secure, self-serve API keys in minutes"

  spec.description = "Add secure, production-ready API key authentication to your Rails app in minutes. Handles key generation, hashing, expiration, revocation, per-key scopes; plus a drop-in dashboard for your users to self-issue and manage their own API keys."

  spec.homepage = "https://github.com/rameerez/api_keys"
  spec.license = "MIT"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["allowed_push_host"] = "https://rubygems.org"
  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = spec.homepage
  spec.metadata["changelog_uri"] = "#{spec.homepage}/blob/main/CHANGELOG.md"
  spec.metadata["rubygems_mfa_required"] = "true"

  # Specify which files should be added to the gem when it is released.
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  gemspec = File.basename(__FILE__)
  spec.files = IO.popen(%w[git ls-files -z], chdir: __dir__, err: IO::NULL) do |ls|
    ls.readlines("\x0", chomp: true).reject do |f|
      (f == gemspec) ||
        f.start_with?(*%w[bin/ test/ spec/ features/ .git .github appveyor Gemfile])
    end
  end
  spec.bindir = "exe"
  spec.executables = spec.files.grep(%r{\Aexe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  # Prevent pushing this gem to RubyGems.org by setting 'allowed_push_host', or
  # delete this section to allow pushing this gem to any host.
  # spec.metadata["allowed_push_host"] = "TODO: Set to your gem server host" # TODO: Configure if needed

  # Runtime Dependencies
  spec.add_dependency "rails", ">= 6.1" # Requires Rails 6+
  spec.add_dependency "activerecord", ">= 6.0"
  spec.add_dependency "activesupport", ">= 6.0"
  spec.add_dependency "base58", "~> 0.2"    # For Base58 token alphabet
  spec.add_dependency "bcrypt", "~> 3.1"    # For secure token hashing

  # Development Dependencies
  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "rake", "~> 13.0"
  # TODO: Add testing framework (e.g., minitest or rspec)
  # TODO: Add linter (e.g., rubocop)
  # TODO: Add Rails itself for the dummy app testing
end
