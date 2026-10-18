# frozen_string_literal: true

module ApiKeys
  # Controller for managing API keys belonging to the current owner.
  class KeysController < ApplicationController
    ALREADY_SHOWN_ALERT = "This API key's token was already shown and cannot be shown again. " \
                          "If you did not save it, revoke this key and create a new one."

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
      # Key is set by set_api_key. The plaintext token comes from the one-time
      # session handoff written by create; it is released once, ever. This
      # action opens no database transaction, so the durable claim commits
      # before the token is rendered; keep it that way (inside a transaction
      # the claim could be rolled back, see ApiKeys::TokenSession).
      retrieval = ApiKeys::TokenSession.retrieve_once_with_status(session, api_key: @api_key)
      @plaintext_token = retrieval.token
      return if @plaintext_token

      # A replayed copy of the session, or a refresh after the token page,
      # gets an explicit answer instead of the generic one.
      alert = if retrieval.already_shown? || @api_key.token_shown?
                ALREADY_SHOWN_ALERT
              else
                "API key token can only be shown once immediately after creation."
              end
      redirect_to keys_path, alert: alert
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

      # A `scopes: :ceiling` type is authorized by its live permissions, so
      # the form offers no scopes for it and any submitted (cleared boxes, or
      # a crafted request) are ignored. The key stores the type's current
      # ceiling as its metadata.
      type_config = requested_key_type_config(submitted_params[:key_type])
      scopes = if ApiKeys::ApiKey.scopes_follow_ceiling_for?(type_config)
                 type_config[:permissions].map(&:to_s)
               else
                 submitted_params[:scopes]
               end

      # Use the HasApiKeys helper method to create the key
      begin
        # create_api_key! now returns the ApiKey instance
        @api_key = current_api_keys_owner.create_api_key!(
          name: submitted_params[:name],
          scopes: scopes,
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
      else
        # The form speaks only for the scopes it offered (see
        # ApiKey#scopes_after_form_edit). Without a scopes parameter (no boxes
        # were shown) it still drops held scopes the current ceiling excludes,
        # or no edit of such a key could ever be saved.
        edited = @api_key.scopes_after_form_edit(offered: dashboard_scope_choices, checked: attributes[:scopes])
        attributes[:scopes] = edited if attributes.key?(:scopes) || edited != Array(@api_key.scopes)
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

    # The configuration of the key type a create request resolves to, the way
    # create_api_key! resolves it (the submitted type, else the default), or
    # nil when there is none or it is unknown.
    #
    # @return [Hash, nil]
    def requested_key_type_config(key_type_param)
      type_name = key_type_param.presence || ApiKeys.configuration.default_key_type
      return nil if type_name.blank?

      (ApiKeys.configuration.key_types || {}).find { |name, _settings| name.to_s == type_name.to_s }&.last
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
