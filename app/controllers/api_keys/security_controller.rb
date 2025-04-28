# frozen_string_literal: true

module ApiKeys
  # Controller for static informational pages within the engine.
  class SecurityController < ApplicationController
    # Skip the user authentication requirement for these static pages
    # as they contain general information.
    skip_before_action :authenticate_api_keys_user!, only: [:best_practices]

    # GET /security/best-practices
    def best_practices
      # Renders app/views/api_keys/security/best_practices.html.erb
      # The view will contain the static content.
    end
  end
end
