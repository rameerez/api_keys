# frozen_string_literal: true

module ApiKeys
  # Controller for managing API keys belonging to the current user.
  class KeysController < ApplicationController
    before_action :set_api_key, only: [:show, :edit, :update, :revoke]

    # GET /keys
    def index
      # Fetch only active keys for the main list, maybe sorted by creation date
      @api_keys = current_api_keys_user.api_keys.active.order(created_at: :desc)
      # Optionally, fetch inactive ones for a separate section or filter
      @inactive_api_keys = current_api_keys_user.api_keys.inactive.order(created_at: :desc)
    end

    # GET /keys/:id
    # Shows the newly generated key's plaintext token ONCE.
    # This is not a standard show action, it's used transiently after creation.
    def show
      # Key is set by set_api_key
      # We need to retrieve the plaintext token stored temporarily
      # after creation. This relies on how we handle creation.
      # We'll likely store it in the session flash or pass it directly.
      @plaintext_token = session.delete(:plaintext_api_key) # Retrieve and delete from session
      unless @plaintext_token
        # If accessed directly without the token, redirect or show an error
        redirect_to keys_path, alert: "API key token can only be shown once immediately after creation."
      end
    end

    # GET /keys/new
    def new
      @api_key = current_api_keys_user.api_keys.build
    end

    # POST /keys
    def create
      # Use the HasApiKeys helper method to create the key
      begin
        # create_api_key! now returns the ApiKey instance
        @api_key = current_api_keys_user.create_api_key!(
          name: api_key_params[:name],
          scopes: api_key_params[:scopes],
          expires_at: parse_expiration(api_key_params[:expires_at_preset])
          # Metadata could be added here if needed
        )

        # Get the plaintext token from the instance's attr_reader
        plaintext_token = @api_key.token

        # Store the plaintext token in session to display on the show page
        session[:plaintext_api_key] = plaintext_token

        redirect_to key_path(@api_key)
      rescue ActiveRecord::RecordInvalid => e
        # If create! fails due to validation (e.g., quota exceeded)
        @api_key = e.record # Get the invalid ApiKey instance
        flash.now[:alert] = "Failed to create API key: #{e.record.errors.full_messages.join(', ')}"
        render :new, status: :unprocessable_entity
      rescue => e # Catch other potential errors
        flash.now[:alert] = "An unexpected error occurred: #{e.message}"
        @api_key = current_api_keys_user.api_keys.build(api_key_params) # Rebuild form
        render :new, status: :unprocessable_entity
      end
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
    end

    # POST /keys/:id/revoke
    def revoke
      if @api_key.revoke!
        redirect_to keys_path, notice: "API key revoked successfully."
      else
        # This shouldn't typically fail unless there's a callback issue
        redirect_to keys_path, alert: "Failed to revoke API key."
      end
    end

    private

    # Use callbacks to share common setup or constraints between actions.
    def set_api_key
      @api_key = current_api_keys_user.api_keys.find(params[:id])
    rescue ActiveRecord::RecordNotFound
      redirect_to keys_path, alert: "API key not found."
    end

    # Only allow a list of trusted parameters through for creation.
    # Added :expires_at_preset for the dropdown selector.
    def api_key_params
      permitted_params = params.require(:api_key).permit(:name, :expires_at_preset, scopes: [])
      permitted_params[:scopes]&.reject!(&:blank?) # Filter out blank strings
      permitted_params
    end

    # Only allow updating name and scopes.
    def api_key_update_params
      permitted_params = params.require(:api_key).permit(:name, scopes: [])
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
      else nil # Default to no expiration if invalid preset
      end
    end
  end
end
