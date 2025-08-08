# frozen_string_literal: true

require "test_helper"
require "active_job"

# Stub helper_method for non-Rails controller context
module Kernel
  def helper_method(*); end
end

module ApiKeys
  class AuthenticationConcernTest < ApiKeys::Test
    class FakeRequest
      attr_reader :headers, :query_parameters, :protocol
      def initialize(headers: {}, query_parameters: {}, protocol: "https://", uuid: SecureRandom.uuid)
        @headers = headers
        @query_parameters = query_parameters
        @protocol = protocol
        @uuid = uuid
      end
      def uuid
        @uuid
      end
    end

    # Minimal controller-like object including the concern
    class FakeController
      include ApiKeys::Authentication

      attr_reader :rendered
      def initialize(request)
        @request = request
        @rendered = nil
      end

      def request
        @request
      end

      def render(json:, status:)
        @rendered = { json: json, status: status }
      end
    end

    def setup
      super
      ActiveJob::Base.queue_adapter = :test
    end

    def clear_enqueued_jobs
      ActiveJob::Base.queue_adapter.enqueued_jobs.clear
      ActiveJob::Base.queue_adapter.performed_jobs.clear if ActiveJob::Base.queue_adapter.respond_to?(:performed_jobs)
    end

    test "authenticate_api_key! success enqueues callbacks and stats job and sets helpers" do
      user = User.create!(name: "Controller User")
      key = ApiKeys::ApiKey.create!(owner: user, name: "Controller Key")
      token = key.instance_variable_get(:@token)
      request = FakeRequest.new(headers: { "Authorization" => "Bearer #{token}" })
      controller = FakeController.new(request)

      ApiKeys.configure do |c|
        c.enable_async_operations = true
        c.track_requests_count = true
        c.before_authentication = ->(ctx) { ctx }
        c.after_authentication  = ->(ctx) { ctx }
      end

      clear_enqueued_jobs
      controller.send(:authenticate_api_key!)

      # Helpers populated
      assert_equal key, controller.send(:current_api_key)
      assert_equal user, controller.send(:current_api_owner)
      assert_equal user, controller.send(:current_api_user)

      # Jobs enqueued: before + after callbacks + stats
      jobs = ActiveJob::Base.queue_adapter.enqueued_jobs
      job_classes = jobs.map { |j| j[:job] }
      assert job_classes.count { |jc| jc == ApiKeys::Jobs::CallbacksJob } >= 2
      assert_includes job_classes, ApiKeys::Jobs::UpdateStatsJob
    end

    test "authenticate_api_key! missing scope renders error and does not enqueue stats" do
      user = User.create!(name: "Scoped User")
      key = ApiKeys::ApiKey.create!(owner: user, name: "Scoped Key", scopes: ["read"]) # no 'write'
      token = key.instance_variable_get(:@token)
      request = FakeRequest.new(headers: { "Authorization" => "Bearer #{token}" })
      controller = FakeController.new(request)

      ApiKeys.configure do |c|
        c.enable_async_operations = true
        c.before_authentication = ->(ctx) { ctx }
        c.after_authentication  = ->(ctx) { ctx }
      end

      clear_enqueued_jobs
      controller.send(:authenticate_api_key!, scope: "write")

      # Rendered unauthorized with missing scope
      resp = controller.rendered
      assert_equal :unauthorized, resp[:status]
      assert_equal :missing_scope, resp[:json][:error]
      assert_equal "write", resp[:json][:required_scope]

      # Stats job not enqueued
      jobs = ActiveJob::Base.queue_adapter.enqueued_jobs
      job_classes = jobs.map { |j| j[:job] }
      refute_includes job_classes, ApiKeys::Jobs::UpdateStatsJob
      # But callbacks are still enqueued (before and after)
      assert job_classes.count { |jc| jc == ApiKeys::Jobs::CallbacksJob } >= 2
    end

    test "authenticate_api_key! with async disabled enqueues no jobs" do
      user = User.create!(name: "No Async User")
      key = ApiKeys::ApiKey.create!(owner: user, name: "No Async Key")
      token = key.instance_variable_get(:@token)
      request = FakeRequest.new(headers: { "Authorization" => "Bearer #{token}" })
      controller = FakeController.new(request)

      ApiKeys.configure do |c|
        c.enable_async_operations = false
        c.track_requests_count = true
        c.before_authentication = ->(ctx) { ctx }
        c.after_authentication  = ->(ctx) { ctx }
      end

      clear_enqueued_jobs
      controller.send(:authenticate_api_key!)

      jobs = ActiveJob::Base.queue_adapter.enqueued_jobs
      job_classes = jobs.map { |j| j[:job] }
      refute_includes job_classes, ApiKeys::Jobs::CallbacksJob
      refute_includes job_classes, ApiKeys::Jobs::UpdateStatsJob
    end

    test "authenticate_api_key! with multiple required scopes succeeds only if all present" do
      user = User.create!(name: "Multi Scope User")
      key = ApiKeys::ApiKey.create!(owner: user, name: "Multi", scopes: %w[read write])
      token = key.instance_variable_get(:@token)
      request = FakeRequest.new(headers: { "Authorization" => "Bearer #{token}" })
      controller = FakeController.new(request)

      ApiKeys.configure { |c| c.enable_async_operations = false }

      # Succeeds when both required
      controller.send(:authenticate_api_key!, scope: %w[read write])
      assert_nil controller.rendered, "Should not render when authorized"

      # Fails when one required scope missing
      key_missing = ApiKeys::ApiKey.create!(owner: user, name: "Missing", scopes: %w[read])
      token2 = key_missing.instance_variable_get(:@token)
      controller2 = FakeController.new(FakeRequest.new(headers: { "Authorization" => "Bearer #{token2}" }))
      controller2.send(:authenticate_api_key!, scope: %w[read write])
      refute_nil controller2.rendered
      assert_equal :missing_scope, controller2.rendered[:json][:error]
      assert_equal %w[read write], controller2.rendered[:json][:required_scope]
    end
  end
end