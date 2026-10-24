# frozen_string_literal: true

require "active_support/concern"
require_relative "authentication"

module ApiKeys
  # Writes that run once per Idempotency-Key, for an API controller that
  # authenticates with `authenticate_api_key!`
  # (draft-ietf-httpapi-idempotency-key-header, ApiKeys::IdempotencyKey):
  #
  #   class Api::BaseController < ActionController::API
  #     include ApiKeys::Controller
  #     include ApiKeys::Idempotency
  #
  #     before_action :authenticate_api_key!
  #     around_action :run_once_per_idempotency_key
  #
  #     private
  #
  #     # The JSON for a record: the first answer and every retry use it.
  #     def resource_json(record, **options)
  #       record.as_json(only: %i[id name])
  #     end
  #   end
  #
  #   class Api::ProjectsController < Api::BaseController
  #     def create
  #       render_resource current_api_owner.projects.create!(project_params), status: :created
  #     end
  #   end
  #
  # Every request but GET and HEAD needs the header. A write answers with
  # `render_resource`, so the key keeps the record it made or changed, and a
  # retry with the same key and the same request answers that record as it
  # is now, with `Idempotent-Replayed: true`. Refusals render through
  # `render_unauthorized`, like the gem's other refusals:
  #
  #   400 idempotency_key_required   no header, or longer than 255 characters
  #   409 idempotency_key_in_use     a request with this key still runs
  #   422 idempotency_key_reused     the key was used for another request
  module Idempotency
    extend ActiveSupport::Concern
    include ApiKeys::Authentication

    REPLAYED_HEADER = "Idempotent-Replayed"

    private

    # The around_action. A write and its answer commit together; a refused
    # write (any status but 2xx) or an error commits nothing and leaves the
    # key free for the next attempt.
    def run_once_per_idempotency_key
      return yield if reading_request?
      raise ApiKeys::Error, "run authenticate_api_key! before run_once_per_idempotency_key" unless current_api_key

      key = request.headers[ApiKeys::IdempotencyKey::HEADER].to_s
      if key.blank? || key.length > ApiKeys::IdempotencyKey::MAX_LENGTH
        return render_unauthorized(
          error_code: :idempotency_key_required, status: :bad_request,
          message: "Send an Idempotency-Key header with every write: a unique text of " \
                   "1 to #{ApiKeys::IdempotencyKey::MAX_LENGTH} characters, the same when you retry."
        )
      end

      ApiKeys::IdempotencyKey.hold(current_api_key, key) do |record|
        next replay_idempotent_request(record) if record.answered?

        record.update!(request_digest: idempotency_request_digest)
        yield
        response.successful? ? record.answer!(response.status, @api_keys_idempotent_resource) : raise(ActiveRecord::Rollback)
      end
    rescue ApiKeys::IdempotencyKey::Busy
      render_unauthorized(error_code: :idempotency_key_in_use, status: :conflict,
                          message: "A request with this Idempotency-Key is still running. Retry in a moment.")
    end

    # A write's answer: the record it made or changed, as `resource_json`
    # renders it. The key keeps the record, so a retry answers the same way.
    # Options go to `resource_json` for this answer only: a secret shown
    # once is never in a retry's answer.
    def render_resource(record, status: :ok, **options)
      @api_keys_idempotent_resource = record
      render json: resource_json(record, **options), status: status
    end

    # The JSON for a record. Define it in the host controller.
    def resource_json(_record, **_options)
      raise NotImplementedError,
            "#{self.class.name} must define resource_json(record, **options) for ApiKeys::Idempotency"
    end

    # The answer to a retry: the record as it is now, never a stored body,
    # so it is current and holds no secret. A record that no longer exists
    # is not found (ActiveRecord::RecordNotFound, which Rails answers 404).
    def replay_idempotent_request(record)
      if record.request_digest != idempotency_request_digest
        return render_unauthorized(error_code: :idempotency_key_reused, status: 422,
                                   message: "This Idempotency-Key was used for another request. Use a new key.")
      end

      resource = record.resource
      raise ActiveRecord::RecordNotFound, "the record of this Idempotency-Key no longer exists" unless resource

      response.headers[REPLAYED_HEADER] = "true"
      render json: resource_json(resource), status: record.response_status
    end

    # The request a key stands for: the method, the path, and every
    # parameter of the query and the body.
    def idempotency_request_digest
      @api_keys_idempotency_request_digest ||= ApiKeys::IdempotencyKey.digest_of(
        request.request_method, request.path, request.query_parameters.merge(request.request_parameters)
      )
    end
  end
end
