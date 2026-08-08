# frozen_string_literal: true

# Test against multiple Rails versions
# This is our most critical dependency point

appraise "rails-7.2" do
  # Active Support 7.2 requires Minitest < 6. Keep the default/8.x suites on
  # Minitest 6 while exercising 7.2 with its latest compatible Minitest.
  gem "minitest", "~> 5.25"
  group :development, :test do
    remove_gem "minitest"
  end
  gem "rails", ">= 7.2.3.2", "< 8.0.a"
end

appraise "rails-8.0" do
  gem "rails", ">= 8.0.5.1", "< 8.1.a"
end

# Test against Rails 8.1 (latest)
appraise "rails-8.1" do
  gem "rails", ">= 8.1.3.1", "< 8.2.a"
end
