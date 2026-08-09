# frozen_string_literal: true

require "test_helper"

module ApiKeys
  class ParentInheritanceTest < ApiKeys::Test
    test "engine application controller inherits from the public parent controller setting" do
      require "action_controller/railtie"
      original_controller = ApiKeys::ApplicationController if ApiKeys.const_defined?(:ApplicationController, false)
      custom_parent = Class.new(ActionController::Base)
      ApiKeys.configuration.parent_controller = custom_parent

      ApiKeys.send(:remove_const, :ApplicationController) if original_controller
      load File.expand_path("../app/controllers/api_keys/application_controller.rb", __dir__)

      assert_same custom_parent, ApiKeys::ApplicationController.superclass
    ensure
      if defined?(original_controller) && original_controller
        ApiKeys.send(:remove_const, :ApplicationController) if ApiKeys.const_defined?(:ApplicationController, false)
        ApiKeys.const_set(:ApplicationController, original_controller)
      end
    end
  end
end
