# frozen_string_literal: true

module Apikeys
  # Rails engine for Apikeys
  class Engine < ::Rails::Engine
    isolate_namespace Apikeys

    initializer "apikeys.configs" do
      # Initialize any config settings
    end
  end
end
