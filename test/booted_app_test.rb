# frozen_string_literal: true

require "test_helper"
require "open3"
require "rbconfig"

# Runs test/support/booted_app.rb, a small Rails application with the
# engine, in a process of its own.
class BootedAppTest < ApiKeys::Test
  test "a booted Rails application filters the device flow's codes from its log, and shares the approval budget" do
    script = File.expand_path("support/booted_app.rb", __dir__)
    output, status = Open3.capture2e(RbConfig.ruby, "-I", File.expand_path("../lib", __dir__), script)

    assert status.success?, output
    assert_match(/3 runs, \d+ assertions, 0 failures, 0 errors/, output)
  end
end
