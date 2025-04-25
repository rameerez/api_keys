# frozen_string_literal: true

module Apikeys
  # Railtie for Rails integration
  class Railtie < Rails::Railtie
    railtie_name :usage_credits

    # Set up action view helpers if needed
    initializer "usage_credits.action_view" do
      ActiveSupport.on_load :action_view do
        require "usage_credits/helpers/credits_helper"
        include Apikeys::CreditsHelper
      end
    end

  end
end
