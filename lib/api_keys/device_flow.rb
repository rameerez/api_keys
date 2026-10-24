# frozen_string_literal: true

require "active_support/concern"

module ApiKeys
  # The two endpoints of the OAuth 2.0 Device Authorization Grant (RFC 8628)
  # for an API controller of the host app: `create` is the device
  # authorization endpoint (§3.1, §3.2), and `token` is the token endpoint
  # that the client polls (§3.4, §3.5). The host routes them and names the
  # page where a person approves (ApiKeys::DeviceAuthorization#approve!):
  #
  #   class Api::DeviceAuthorizationsController < ActionController::API
  #     include ApiKeys::DeviceFlow
  #
  #     private
  #
  #     def device_verification_uri(user_code = nil)
  #       device_approval_url(code: user_code)
  #     end
  #   end
  #
  #   post "api/device", to: "api/device_authorizations#create"
  #   post "api/token", to: "api/device_authorizations#token"
  #
  # Neither request carries a key. Errors follow RFC 6749 §5.2
  # (`{ error, error_description }`, status 400), as OAuth device clients
  # expect, and no answer may be cached (RFC 6749 §5.1).
  module DeviceFlow
    extend ActiveSupport::Concern

    GRANT_TYPE = "urn:ietf:params:oauth:grant-type:device_code" # RFC 8628 §3.4

    # Override any of them with I18n: api_keys.device_flow.errors.<error>.
    ERROR_DESCRIPTIONS = {
      "authorization_pending" => "The person has not decided yet. Poll again after the interval.",
      "slow_down" => "Polled too soon. Wait 5 seconds longer between polls from now on.",
      "access_denied" => "The person denied the request.",
      "expired_token" => "The codes expired. Ask for new ones.",
      "invalid_grant" => "This device code is unknown, was used already, or belongs to another client_id.",
      "unsupported_grant_type" => "Send grant_type=#{GRANT_TYPE}.",
      "invalid_scope" => "Ask for scopes among: %{scopes}.",
      "invalid_request" => "Send client_id, the client's name, and device_name, the device's name: " \
                           "at most #{ApiKeys::DeviceAuthorization::MAX_NAME_LENGTH} characters each."
    }.freeze

    # RFC 8628 §3.1 and §3.2. `scope` lists the scopes, space-separated
    # (RFC 6749 §3.3). A client may ask for any of `config.default_scopes`.
    def create
      scopes = params.fetch(:scope) { device_default_scope }.to_s.split.uniq
      if scopes.empty? || (scopes - ApiKeys::DeviceAuthorization.grantable_scopes).any?
        return render_oauth_error("invalid_scope")
      end

      authorization = ApiKeys::DeviceAuthorization.request!(
        client_id: params[:client_id].to_s.strip, device_name: params[:device_name].to_s.strip.presence,
        scopes: scopes, requested_from: ApiKeys.configuration.client_ip_resolver.call(request)
      )
      render_without_cache json: {
        device_code: authorization.device_code, user_code: authorization.user_code,
        verification_uri: device_verification_uri,
        verification_uri_complete: device_verification_uri(authorization.user_code),
        expires_in: ApiKeys::DeviceAuthorization::LIFETIME.to_i, interval: authorization.interval
      }
    rescue ActiveRecord::RecordInvalid
      render_oauth_error("invalid_request")
    end

    # RFC 8628 §3.4 and §3.5. The answer that carries the token is the only
    # one there is. A poll from another client_id changes nothing, so the
    # grant waits for its own client.
    def token
      return render_oauth_error("unsupported_grant_type") unless params[:grant_type] == GRANT_TYPE

      authorization = ApiKeys::DeviceAuthorization.find_by_device_code(params[:device_code])
      return render_oauth_error("invalid_grant") unless authorization

      poll = nil
      body = ApiKeys::DeviceAuthorization.transaction do
        poll = authorization.poll!(client_id: params[:client_id])
        device_token_response(authorization, poll.api_key) if poll.api_key
      end
      return render_oauth_error(poll.error) if poll.error

      render_without_cache json: body
    end

    private

    # The approval page of the host app, with the user code filled in when
    # one is given (`verification_uri_complete`, RFC 8628 §3.3.1).
    def device_verification_uri(_user_code = nil)
      raise NotImplementedError,
            "#{self.class.name} must define device_verification_uri(user_code = nil): the URL of its approval page"
    end

    # The scope a request without `scope` asks for, space-separated. With
    # nil (the default) such a request fails with invalid_scope, as RFC 6749
    # §3.3 allows.
    def device_default_scope
      nil
    end

    # The token response (RFC 6749 §5.1). It runs in the transaction that
    # creates the key, so a row it writes (an audit entry) commits with the
    # key, or neither does. Override it to add fields, and call super.
    def device_token_response(_authorization, api_key)
      { access_token: api_key.token, token_type: "Bearer", scope: api_key.scopes.join(" ") }
    end

    # An error response (RFC 6749 §5.2). A rate limit's `with:` can use it:
    #   rate_limit to: 20, within: 1.hour, only: :create,
    #     with: -> { render_oauth_error("slow_down", "Too many requests.", status: :too_many_requests) }
    def render_oauth_error(error, description = nil, status: :bad_request)
      description ||= I18n.t("api_keys.device_flow.errors.#{error}", default: ERROR_DESCRIPTIONS[error].to_s,
                                                                     scopes: ApiKeys::DeviceAuthorization.grantable_scopes.join(" "))
      render_without_cache json: { error: error, error_description: description.presence }.compact, status: status
    end

    # RFC 6749 §5.1: an answer that carries a credential is never cached.
    def render_without_cache(**options)
      response.headers["Cache-Control"] = "no-store"
      response.headers["Pragma"] = "no-cache"
      render(**options)
    end
  end
end
