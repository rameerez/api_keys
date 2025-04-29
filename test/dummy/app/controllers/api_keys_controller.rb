# frozen_string_literal: true

class ApiKeysController < ApplicationController
  # Include the core authentication logic from the gem
  include ApiKeys::Authentication
  # Include tenant resolution helpers (optional, but good for demo)
  include ApiKeys::TenantResolution

  # ====
  # Demonstration Endpoints for API Key Authentication
  # ====

  # --- Public Action --- (No Auth)
  # GET /demo_api/public
  def public_action
    render json: {
      status: "success",
      message: "This action is public and does not require an API key.",
      timestamp: Time.current
    }, status: :ok
  end

  # --- Authenticated Action --- (Valid Key, No Scope Check)
  # GET /demo_api/authenticated
  before_action -> { authenticate_api_key! }, only: [:authenticated_action]
  def authenticated_action
    render json: {
      status: "success",
      message: "Authenticated action successful!",
      key_id: current_api_key&.id,
      key_name: current_api_key&.name,
      owner_email: current_api_owner&.email, # Use owner helper
      timestamp: Time.current
    }, status: :ok
  end

  # --- Read Action --- (Requires 'read' scope)
  # GET /demo_api/scoped/read
  before_action -> { authenticate_api_key!(scope: "read") }, only: [:read_action]
  def read_action
    render json: {
      status: "success",
      message: "Read action successful (scope 'read' granted).",
      key_id: current_api_key&.id,
      key_name: current_api_key&.name,
      key_scopes: current_api_key&.scopes,
      owner_email: current_api_owner&.email,
      timestamp: Time.current
    }, status: :ok
  end

  # --- Write Action --- (Requires 'write' scope)
  # GET or POST /demo_api/scoped/write
  before_action -> { authenticate_api_key!(scope: "write") }, only: [:write_action]
  def write_action
    render json: {
      status: "success",
      message: "Write action successful (scope 'write' granted). Method: #{request.method}",
      key_id: current_api_key&.id,
      key_name: current_api_key&.name,
      key_scopes: current_api_key&.scopes,
      owner_email: current_api_owner&.email,
      timestamp: Time.current
    }, status: :ok
  end

  # --- Admin Action --- (Requires 'admin' scope)
  # GET or POST /demo_api/scoped/admin
  before_action -> { authenticate_api_key!(scope: "admin") }, only: [:admin_action]
  def admin_action
    render json: {
      status: "success",
      message: "Admin action successful (scope 'admin' granted). Method: #{request.method}",
      key_id: current_api_key&.id,
      key_name: current_api_key&.name,
      key_scopes: current_api_key&.scopes,
      owner_email: current_api_owner&.email,
      timestamp: Time.current
    }, status: :ok
  end


  # ====
  # Index page for the demo app
  # ====
  def index
    # No specific action needed here, view will render user info and keys
    @api_keys = current_user.api_keys.order(created_at: :desc)
  end

  # Note: We are removing the create_key action as per the instructions
  # to focus solely on *usage* demonstration initially.

  # Note: The render_scope_error method is now handled internally by
  # the authenticate_api_key! method when a scope check fails.
end
