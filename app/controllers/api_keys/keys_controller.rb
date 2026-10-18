# frozen_string_literal: true

module ApiKeys
  # Controller for managing API keys belonging to the current owner.
  class KeysController < ApplicationController
    before_action :set_api_key, only: [:show, :edit, :update, :revoke]
    helper ApiKeys::Helpers::ViewHelpers
    helper_method :key_types_feature_enabled?, :api_keys_allowed_restriction_kinds,
                  :dashboard_scope_choices, :restriction_field_text, :api_keys_displayed_scopes

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
      @api_key = current_api_keys_owner.api_keys.build(key_type: ApiKeys.configuration.default_key_type)
    end

    # POST /keys
    def create
      submitted_params = api_key_params
      # If creation fails, the re-rendered form shows these instead of
      # re-checking every scope the owner had cleared.
      @submitted_scopes = submitted_params[:scopes]

      # Use the HasApiKeys helper method to create the key
      begin
        # create_api_key! now returns the ApiKey instance
        @api_key = current_api_keys_owner.create_api_key!(
          name: submitted_params[:name],
          scopes: submitted_params[:scopes],
          expires_at: parse_expiration(submitted_params[:expires_at_preset]),
          key_type: submitted_params[:key_type].presence,
          # The model normalizes these raw strings; no parser needed here.
          allowed_origins: submitted_params[:allowed_origins],
          allowed_ips: submitted_params[:allowed_ips]
          # Metadata could be added here if needed
        )

        # Store the plaintext token in session to display on the show page
        ApiKeys::TokenSession.store(session, @api_key)

        redirect_to key_path(@api_key)
      rescue ActiveRecord::RecordInvalid => e
        # If create! fails due to validation (e.g., quota exceeded)
        @api_key = e.record # Get the invalid ApiKey instance
        @api_key.expires_at_preset = submitted_params[:expires_at_preset]
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
      attributes = api_key_update_params
      if @api_key.scopes_follow_ceiling?
        # The type's live ceiling authorizes this key and its stored scopes are
        # metadata. The form offers no scope boxes for it, so any submitted
        # scopes (the sentinel, or a crafted request) are ignored, and held
        # scopes outside a narrowed ceiling are kept: the model lets such a key
        # save as long as its scopes are not written.
        attributes.delete(:scopes)
      elsif attributes.key?(:scopes)
        attributes[:scopes] = scopes_after_editing_offered_choices(attributes[:scopes])
      elsif held_scopes_within_ceiling != Array(@api_key.scopes)
        # No scope boxes were shown, but the key still holds a scope its type
        # no longer allows; without dropping it no edit could ever be saved.
        attributes[:scopes] = held_scopes_within_ceiling
      end
      skip_untouched_restriction_fields!(attributes)

      if @api_key.update(attributes)
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

      permitted_params = submitted.permit(:name, :expires_at_preset, :key_type,
                                          :allowed_origins, :allowed_ips, scopes: [])
      normalize_submitted_scopes!(permitted_params)
    end

    # Each scope checkbox group renders an empty sentinel (`scopes[]=""`), so a
    # submitted form always carries the parameter. Stripping blanks turns the
    # sentinel alone into `[]`: the owner cleared every box and means "none",
    # and the model's validations decide whether that is allowed. Only an
    # absent parameter (`nil`) means "not specified": create_api_key! then
    # applies the default scopes and update leaves the current ones alone.
    def normalize_submitted_scopes!(permitted_params)
      permitted_params[:scopes]&.reject!(&:blank?)
      permitted_params
    end

    # The scopes the dashboard offers as checkboxes: the owner's configured
    # default scopes. The form renders exactly this list, and an update edits
    # only scopes in it.
    #
    # @return [Array<String>]
    def dashboard_scope_choices
      Array(current_api_keys_owner.class.api_keys_settings.dig(:default_scopes))
    end

    # The edit form can only speak for the scopes it showed. Checked choices
    # are granted and unchecked ones removed; any other scope the key holds
    # (for example one granted programmatically, or a type permission outside
    # the owner's defaults) is kept, in its current order. A submitted value
    # that was never offered is ignored.
    #
    # A held scope outside the key's current ceiling is dropped, whether
    # offered or not: authentication already denies it, so no access changes,
    # and keeping it would make every save of the key (a rename, or tightening
    # a non-revocable key's origins) fail the ceiling validation. A newly
    # checked scope outside the ceiling is kept, so validation reports it.
    #
    # @param submitted [Array<String>] Checked boxes, sentinel already stripped.
    # @return [Array<String>]
    def scopes_after_editing_offered_choices(submitted)
      offered = dashboard_scope_choices
      held = Array(@api_key.scopes)
      kept = held_scopes_within_ceiling.select { |scope| !offered.include?(scope) || submitted.include?(scope) }
      added = offered.select { |scope| submitted.include?(scope) && !held.include?(scope) }
      kept + added
    end

    # The key's scopes without those its current ceiling excludes.
    #
    # @return [Array<String>]
    def held_scopes_within_ceiling
      Array(@api_key.scopes).select { |scope| @api_key.scope_within_ceiling?(scope) }
    end

    # The text the form puts in a restriction field. Usable entries appear as
    # they are stored; anything else a stored policy holds (null, false, a
    # number, a blank string) is shown as JSON, so the owner can see it.
    #
    # @return [String]
    def restriction_field_text(api_key, kind)
      api_key.restrictions.public_send(kind).map do |entry|
        if entry.is_a?(String) && entry.valid_encoding? && !entry.strip.empty?
          entry
        else
          begin
            JSON.generate(entry)
          rescue StandardError
            entry.inspect
          end
        end
      end.join(", ")
    end

    # A restriction field submitted exactly as it was rendered was not
    # touched, so its kind is left alone. Re-parsing the text would rewrite
    # the stored list, and a malformed stored entry could come back as an
    # empty (unrestricted) list or as a different, valid one. Left alone, a
    # malformed stored policy keeps failing validation, so the save is refused
    # until the owner corrects the field.
    def skip_untouched_restriction_fields!(attributes)
      { allowed_origins: :origins, allowed_ips: :ips }.each do |field, kind|
        next unless attributes.key?(field)

        attributes.delete(field) if attributes[field] == restriction_field_text(@api_key, kind)
      end
    end

    # Only allow updating name, scopes, and request restrictions.
    # Restriction edits stay available on non-revocable keys so an owner can
    # still tighten the policy even when lifecycle operations are disabled.
    def api_key_update_params
      submitted = params.require(:api_key)
      raise ActionController::ParameterMissing, :api_key unless submitted.respond_to?(:permit)

      permitted_params = submitted.permit(:name, :allowed_origins, :allowed_ips, scopes: [])
      normalize_submitted_scopes!(permitted_params)
      permitted_params.delete(:allowed_origins) unless ApiKeys::ApiKey.restrictions_column?
      permitted_params.delete(:allowed_ips) unless ApiKeys::ApiKey.restrictions_column?
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
      api_key = current_api_keys_owner.api_keys.build(
        name: submitted_params[:name],
        scopes: submitted_params[:scopes],
        key_type: submitted_params[:key_type]
      )
      api_key.expires_at_preset = submitted_params[:expires_at_preset]
      if ApiKeys::ApiKey.restrictions_column?
        api_key.allowed_origins = submitted_params[:allowed_origins] unless submitted_params[:allowed_origins].nil?
        api_key.allowed_ips = submitted_params[:allowed_ips] unless submitted_params[:allowed_ips].nil?
      end
      api_key
    end

    # Which restriction kinds the form may offer for a given key.
    # A typed key answers with its own ceiling; an unsaved key that has not
    # picked a type yet offers everything any configured type allows.
    #
    # @param api_key [ApiKeys::ApiKey]
    # @return [Array<Symbol>]
    def api_keys_allowed_restriction_kinds(api_key)
      return api_key.allowed_restriction_kinds if api_key.persisted?
      return ApiKeys::Restrictions::KINDS.dup unless key_types_feature_enabled?

      ApiKeys.configuration.key_types.flat_map do |_type, settings|
        ApiKeys::ApiKey.restriction_kinds_for(settings)
      end.uniq
    end

    # The permissions a key actually has, for display. A `scopes: :ceiling` key
    # is authorized by its type's live ceiling, so showing the list it stored
    # at creation would misstate what it can do.
    #
    # @param api_key [ApiKeys::ApiKey]
    # @return [Array<String>]
    def api_keys_displayed_scopes(api_key)
      return Array(api_key.key_type_config[:permissions]).map(&:to_s) if api_key.scopes_follow_ceiling?

      api_key.scopes.is_a?(Array) ? api_key.scopes : []
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
