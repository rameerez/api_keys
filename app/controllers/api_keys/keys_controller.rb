# frozen_string_literal: true

module ApiKeys
  # Controller for managing API keys belonging to the current owner.
  class KeysController < ApplicationController
    before_action :set_api_key, only: [:show, :edit, :update, :revoke]
    helper_method :key_types_feature_enabled?

    # GET /keys
    def index
      # Start with all keys for the owner
      base_scope = current_api_keys_owner.api_keys

      # Filter by environment if key_types feature is enabled and cross-environment is disabled
      if key_types_feature_enabled? && !ApiKeys.configuration.dashboard_allow_cross_environment
        current_env = resolve_current_environment
        base_scope = base_scope.where(environment: [current_env.to_s, nil, ""])
      end

      # Fetch only active keys for the main list, sorted by creation date
      @api_keys = base_scope.active.order(created_at: :desc)
      # Optionally, fetch inactive ones for a separate section or filter
      @inactive_api_keys = base_scope.inactive.order(created_at: :desc)

      # When key_types feature is enabled, separate publishable and secret keys
      if key_types_feature_enabled?
        @publishable_keys = @api_keys.select(&:public_key_type?)
        @secret_keys = @api_keys.reject(&:public_key_type?)
        @inactive_publishable_keys = @inactive_api_keys.select(&:public_key_type?)
        @inactive_secret_keys = @inactive_api_keys.reject(&:public_key_type?)
      end
    end

    # GET /keys/:id
    # Shows the newly generated key's plaintext token ONCE.
    # This is not a standard show action, it's used transiently after creation.
    def show
      # Key is set by set_api_key
      # We need to retrieve the plaintext token stored temporarily
      # after creation. This relies on how we handle creation.
      # We'll likely store it in the session flash or pass it directly.
      @plaintext_token = ApiKeys::TokenSession.retrieve_once(session, api_key: @api_key)
      unless @plaintext_token
        # If accessed directly without the token, redirect or show an error
        redirect_to keys_path, alert: "API key token can only be shown once immediately after creation."
      end
    end

    # GET /keys/new
    def new
      @api_key = current_api_keys_owner.api_keys.build
    end

    # POST /keys
    def create
      submitted_params = api_key_params

      # Use the HasApiKeys helper method to create the key
      begin
        # create_api_key! now returns the ApiKey instance
        @api_key = current_api_keys_owner.create_api_key!(
          name: submitted_params[:name],
          scopes: submitted_params[:scopes],
          expires_at: parse_expiration(submitted_params[:expires_at_preset]),
          key_type: submitted_params[:key_type].presence
          # Metadata could be added here if needed
        )

        # Store the plaintext token in session to display on the show page
        ApiKeys::TokenSession.store(session, @api_key)

        redirect_to key_path(@api_key)
      rescue ActiveRecord::RecordInvalid => e
        # If create! fails due to validation (e.g., quota exceeded)
        @api_key = e.record # Get the invalid ApiKey instance
        flash.now[:alert] = "Failed to create API key: #{e.record.errors.full_messages.join(', ')}"
        render :new, status: :unprocessable_entity
      rescue ArgumentError
        flash.now[:alert] = "Failed to create API key: invalid options."
        @api_key = rebuild_api_key_for_form(submitted_params)
        render :new, status: :unprocessable_entity
      rescue StandardError => error
        log_error "[ApiKeys Dashboard] Unexpected key creation failure (#{error.class}); request ID: #{request.uuid}"
        flash.now[:alert] = "An unexpected error occurred while creating the API key."
        @api_key = rebuild_api_key_for_form(submitted_params)
        render :new, status: :unprocessable_entity
      end
    rescue ActionController::ParameterMissing
      head :bad_request
    end

    # GET /keys/:id/edit
    def edit
      # Key is set by set_api_key
    end

    # PATCH/PUT /keys/:id
    def update
      if @api_key.update(api_key_update_params)
        redirect_to keys_path, notice: "API key updated successfully."
      else
        flash.now[:alert] = "Failed to update API key: #{@api_key.errors.full_messages.join(', ')}"
        render :edit, status: :unprocessable_entity
      end
    rescue ActionController::ParameterMissing
      head :bad_request
    end

    # POST /keys/:id/revoke
    def revoke
      @api_key.revoke!
      redirect_to keys_path, notice: "API key revoked successfully."
    rescue ApiKeys::Errors::KeyNotRevocableError
      redirect_to keys_path, alert: "This API key cannot be revoked."
    rescue StandardError => error
      log_error "[ApiKeys Dashboard] Unexpected key revocation failure (#{error.class}); key ID: #{@api_key&.id}; request ID: #{request.uuid}"
      redirect_to keys_path, alert: "Failed to revoke API key."
    end

    private

    # Use callbacks to share common setup or constraints between actions.
    def set_api_key
      @api_key = current_api_keys_owner.api_keys.find(params[:id])
    rescue ActiveRecord::RecordNotFound
      redirect_to keys_path, alert: "API key not found."
    end

    # Only allow a list of trusted parameters through for creation.
    # Added :expires_at_preset for the dropdown selector.
    # Added :key_type for the key types feature.
    def api_key_params
      submitted = params.require(:api_key)
      raise ActionController::ParameterMissing, :api_key unless submitted.respond_to?(:permit)

      permitted_params = submitted.permit(:name, :expires_at_preset, :key_type, scopes: [])
      permitted_params[:scopes]&.reject!(&:blank?) # Filter out blank strings
      permitted_params
    end

    # Only allow updating name and scopes.
    def api_key_update_params
      submitted = params.require(:api_key)
      raise ActionController::ParameterMissing, :api_key unless submitted.respond_to?(:permit)

      permitted_params = submitted.permit(:name, scopes: [])
      permitted_params[:scopes]&.reject!(&:blank?) # Filter out blank strings
      permitted_params
    end

    # Helper to parse the expiration preset string into a Time object
    def parse_expiration(preset)
      case preset
      when "7_days" then 7.days.from_now
      when "30_days" then 30.days.from_now
      when "60_days" then 60.days.from_now
      when "90_days" then 90.days.from_now
      when "365_days" then 365.days.from_now
      when "no_expiration" then nil
      when nil, "" then nil
      else raise ArgumentError, "Invalid expiration preset"
      end
    end

    def rebuild_api_key_for_form(submitted_params)
      current_api_keys_owner.api_keys.build(
        name: submitted_params[:name],
        scopes: submitted_params[:scopes]
      )
    end

    # Check if key types feature is enabled
    def key_types_feature_enabled?
      ApiKeys.configuration.key_types.present? && ApiKeys.configuration.key_types.any?
    end

    # Get the current environment from configuration
    def resolve_current_environment
      env_config = ApiKeys.configuration.current_environment
      env_config.respond_to?(:call) ? env_config.call : env_config
    end
  end
end
