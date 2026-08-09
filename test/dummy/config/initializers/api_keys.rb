# frozen_string_literal: true

ApiKeys.configure do |config|
  # === Core Authentication ===

  # The HTTP header name where the API key is expected.
  # Default: "Authorization" (expects "Bearer <token>")
  # config.header = "Authorization"

  # The query parameter name to check as a fallback if the header is missing.
  # Set to nil to disable query parameter lookup (recommended for security).
  # Default: nil
  # Keep URL-based credentials disabled, including in the public demo.
  config.query_param = nil

  # === Token Generation ===

  # A lambda/proc that returns the prefix for newly generated tokens.
  # Defaults to "ak_".
  config.token_prefix = -> { "ak_demo_" }

  # The number of random bytes to generate for the token (before encoding).
  # More bytes = more entropy = harder to guess.
  # Default: 24 (generates ~32 Base58 chars or 48 hex chars)
  # config.token_length = 32

  # The encoding alphabet for the random part of the token.
  # :base58 (recommended) - shorter, avoids ambiguous chars (0, O, I, l)
  # :hex - standard hexadecimal encoding
  # Default: :base58
  # config.token_alphabet = :hex

  # === Storage & Verification ===

  # The hashing strategy used to store token digests in the database.
  # :sha256 (recommended) - fast, performant, O(1) lookups, but less secure if database is compromised (salted with prefix only)
  # :bcrypt - for security-critical tokens: includes salt, computationally expensive, can cause lags, 10x-50x slower than sha256
  # Default: :sha256
  # config.hash_strategy = :bcrypt

  # === Optional Behaviors ===

  # Global limit on the number of *active* keys an owner can have.
  # Can be overridden by `max_keys` in the `has_api_keys` block.
  # Set to nil for no global limit.
  # Default: nil
  # config.default_max_keys_per_owner = 10

  # If true, requires a `name` when creating keys.
  # Can be overridden by `require_name` in the `has_api_keys` block.
  # Default: false
  # config.require_key_name = true

  # Automatically expire keys after a certain period from creation.
  # Set to nil for no automatic expiration.
  # Default: nil
  # config.expire_after = 90.days

  # Default scopes to assign to newly created keys if none are specified.
  # Applies globally unless overridden by `has_api_keys` in the owner model.
  # Default: []
  # config.default_scopes = ["read"]

  # === Performance ===

  # Time-to-live (TTL) for caching ApiKey ID lookup hints. Every hit reloads
  # current database state and re-verifies the token, so the cache cannot delay
  # revocation, expiration, or permission changes.
  # Set to 0 or nil to disable caching.
  # Uses Rails.cache.
  # Default: 5.seconds
  # config.cache_ttl = 30.seconds

  # === Security ===

  # If true, logs a warning if the gem is used over HTTP in production.
  # Default: true
  # config.https_only_production = true

  # If true (and https_only_production is true), rejects authentication over
  # HTTP in production.
  # Default: true
  # config.https_strict_mode = true

  # IMPORTANT: Usage Statistics & Background Jobs
  # ---------------------------------------------
  # The api_keys gem executes callbacks and updates `last_used_at` asynchronously.
  # Timestamp updates are debounced for one minute by default when exact request
  # counting is disabled. Enabling `track_requests_count` necessarily processes
  # every successful authentication.
  # To avoid blocking the request cycle, these calls and updates are performed asynchronously
  # using ActiveJob (`ApiKeys::Jobs::UpdateStatsJob` and `ApiKeys::Jobs::CallbacksJob`)
  #
  # *** For callbacks to be executed, and for reliable and performant usage statistics, you MUST configure a persistent
  # ActiveJob backend adapter in your Rails app! (e.g., Sidekiq, GoodJob, SolidQueue, Resque, Delayed::Job). ***
  #
  # - Using the default :async adapter is NOT recommended for production as updates
  #   run in-process and may be lost if the application restarts unexpectedly.
  # - Using the :inline adapter will perform updates synchronously within the request,
  #   negating the performance benefits and potentially slowing down responses.
  #
  # If you do not have a persistent background job system configured, callbacks won't fire and stats updates
  # might be unreliable or impact performance. Consider disabling `track_requests_count` and avoid using callbacks
  # if you cannot use a persistent backend and performance is critical.

  # === Background Job Queues ===

  # Configure the ActiveJob queue name for processing API key usage statistics.
  # Default: :default
  # config.stats_job_queue = :api_keys_stats

  # Configure the ActiveJob queue name for processing asynchronous callbacks.
  # Default: :default
  # config.callbacks_job_queue = :api_keys_callbacks

  # === Global Async Toggle ===

  # Set to false to completely disable all background job enqueueing performed
  # by this gem (stats updates and callbacks). If false, `last_used_at`,
  # `requests_count`, and configured callbacks will NOT be processed.
  # Useful if you handle these concerns externally or cannot use ActiveJob.
  # Default: true
  # config.enable_async_operations = false

  # === Usage Statistics ===

  # If true, automatically update `last_used_at` and increment `requests_count`
  # on the ApiKey record upon successful authentication.
  # Note: Incrementing counters frequently can impact DB performance.
  # Default: false
  # config.track_requests_count = true

  # Minimum interval between last_used_at jobs when exact request counting is
  # disabled. Set to 0 or nil for per-request timestamp updates.
  # Default: 1.minute
  # config.stats_update_interval = 1.minute

  # === Callbacks ===

  # A lambda/proc enqueued before token extraction and verification.
  # Receives: { request_uuid: String }. It never receives the request or token.
  # Default: ->(context) { }
  # config.before_authentication = ->(context) { Rails.logger.info "Authenticating request: #{context[:request_uuid]}" }

  # A lambda/proc enqueued after authentication (success or failure).
  # Receives a credential-free context hash with success, error_code,
  # api_key_id, and optional required_scope_check fields.
  # Default: ->(context) { }
  # config.after_authentication = ->(context) { MyAnalytics.track_auth(context) }

  # === Engine UI Configuration ===

  # The URL or path helper method (as a string) to link back to from the engine's UI.
  # Useful when embedding the engine within a larger application context.
  # Default: "/" (Root path)
  config.return_url = "/"

  # The text displayed for the return link.
  # Default: "‹ Home"
  config.return_text = "‹ Home"

  # === Debugging ===

  # Enable verbose logging for debugging purposes.
  # Default: false
  # config.debug_logging = true
end
