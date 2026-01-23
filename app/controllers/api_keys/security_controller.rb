# frozen_string_literal: true

module ApiKeys
  # Controller for static informational pages within the engine.
  class SecurityController < ApplicationController
    # Skip the user authentication requirement for these static pages
    # as they contain general information.
    skip_before_action :authenticate_api_keys_owner!, only: [:best_practices]
    helper_method :key_types_feature_enabled?

    # GET /security/best-practices
    def best_practices
      # Renders app/views/api_keys/security/best_practices.html.erb
      # The view will contain the static content.
    end

    private

    # Check if key types feature is enabled
    def key_types_feature_enabled?
      ApiKeys.configuration.key_types.present? && ApiKeys.configuration.key_types.any?
    end
  end
end
