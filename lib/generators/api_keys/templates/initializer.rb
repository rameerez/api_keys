# frozen_string_literal: true

ApiKeys.configure do |config|
  # ============================================================================
  # CORE AUTHENTICATION
  # ============================================================================

  # The HTTP header name where the API key is expected.
  # Default: "Authorization" (expects "Bearer <token>")
  # config.header = "Authorization"

  # The query parameter name to check as a fallback if the header is missing.
  # WARNING: Query parameters appear in logs, browser history, and Referer headers.
  # Only enable for development/testing. Set to nil to disable (recommended).
  # Default: nil
  # config.query_param = "api_key"

  # ============================================================================
  # DASHBOARD CONFIGURATION
  # ============================================================================
  #
  # The api_keys engine provides a web UI for users to manage their API keys.
  # Configure how the dashboard integrates with your application's auth system.
  # ============================================================================

  # The method that returns the current API key owner in your controllers.
  # This should return the model instance that has_api_keys.
  # Default: :current_user (works with Devise out of the box)
  #
  # Example for Organization-owned keys:
  # config.current_owner_method = :current_organization

  # The method that authenticates/requires login for the dashboard.
  # This should be a before_action-style method that ensures the owner is logged in.
  # Default: :authenticate_user! (works with Devise out of the box)
  #
  # Example for Organization-owned keys:
  # config.authenticate_owner_method = :authenticate_organization!

  # Dashboard environment filtering (only applies when key_types is configured).
  # When false (default), dashboard only shows keys matching current_environment.
  # When true, dashboard shows keys from all environments.
  # Default: false
  #
  # config.dashboard_allow_cross_environment = false

  # URL for the "back" link in the dashboard UI.
  # Default: "/"
  # config.return_url = "/settings"

  # Text for the "back" link.
  # Default: "‹ Home"
  # config.return_text = "‹ Back to Settings"

  # ============================================================================
  # TOKEN PREFIXES
  # ============================================================================
  #
  # API keys are generated with a prefix followed by random characters:
  #   "ak_7Hq2mJvK9pRs3xYz..."
  #   prefix        = ak_
  #   random part   = 7Hq2mJvK9pRs3xYz...
  #
  # The prefix system has two modes:
  #
  # 1. SIMPLE MODE (default): All keys use the same prefix from `token_prefix`
  #    Example: ak_7Hq2mJvK9pRs3xYz...
  #
  # 2. KEY TYPES MODE: Different key types get different prefixes based on
  #    their type and environment (Stripe-style)
  #    Example: pk_test_7Hq2mJvK..., sk_live_9xYz3pRs...
  #
  # See "KEY TYPES & ENVIRONMENTS" section below to enable key types mode.

  # ----------------------------------------------------------------------------
  # Simple Prefix (when NOT using KEY TYPES)
  # ----------------------------------------------------------------------------
  #
  # A lambda/proc that returns the prefix for newly generated tokens.
  # This is ONLY used when:
  #   - key_types is not configured (empty hash), OR
  #   - Creating a key without specifying a key_type
  #
  # When key_types IS configured and you specify a key_type, this setting
  # is IGNORED - the prefix comes from the key type's configuration instead.
  #
  # WARNING: Once set, do NOT change or existing keys will fail authentication!
  # Default: -> { "ak_" }
  # config.token_prefix = -> { "myapp_" }

  # ============================================================================
  # KEY TYPES & ENVIRONMENTS (Stripe-style Publishable/Secret Keys)
  # ============================================================================
  #
  # For applications that distribute software with embedded API keys (desktop
  # apps, mobile apps, CLI tools), you can create different key types with
  # different permission levels - similar to Stripe's publishable/secret pattern.
  #
  # When enabled:
  # - Keys get type+environment prefixes: pk_test_, pk_live_, sk_test_, sk_live_
  # - Each type can have different permissions, revocability, and limits
  # - The `token_prefix` setting above is IGNORED for typed keys
  #
  # By default, this feature is DISABLED (empty hash) for backwards compatibility.
  # Existing keys without key_type/environment continue to work normally.
  # ============================================================================

  # Define your key types with their properties:
  #
  # - prefix:      The token prefix for this type (e.g., "pk" becomes pk_test_)
  # - permissions: Scope ceiling - array of allowed scopes, or :all for unrestricted
  # - revocable:   Whether keys of this type can be revoked/deleted (default: true)
  # - limit:       Max keys of this type per owner per environment (nil = unlimited)
  #
  # config.key_types = {
  #   publishable: {
  #     prefix: "pk",                    # → pk_test_, pk_live_
  #     permissions: %w[read validate],  # Can ONLY have these scopes
  #     revocable: false,                # Cannot be revoked - protects deployed apps!
  #     limit: 1                         # Only 1 publishable key per environment
  #   },
  #   secret: {
  #     prefix: "sk",                    # → sk_test_, sk_live_
  #     permissions: :all                # No scope restrictions
  #     # revocable: true (default)
  #     # limit: nil (default = unlimited)
  #   }
  # }

  # Define your environments with their prefix segments:
  #
  # - prefix_segment: The middle part of the prefix (e.g., "test" → pk_test_)
  #   Set to nil for single-environment setups (prefix becomes just "pk_")
  #
  # config.environments = {
  #   test: { prefix_segment: "test" },  # Development/staging → pk_test_, sk_test_
  #   live: { prefix_segment: "live" }   # Production → pk_live_, sk_live_
  # }
  #
  # Alternative naming (Stripe's newer convention):
  # config.environments = {
  #   sandbox: { prefix_segment: "test" },
  #   live: { prefix_segment: "live" }
  # }

  # Lambda that returns the current environment.
  # Used to auto-select environment when creating keys and for isolation checks.
  # Default: -> { :default }
  #
  # config.current_environment = -> { Rails.env.production? ? :live : :test }

  # Enable strict environment isolation.
  # When true, keys can ONLY authenticate in their matching environment:
  # - test keys return :environment_mismatch error in production
  # - live keys return :environment_mismatch error in development/test
  # Default: false
  #
  # config.strict_environment_isolation = true

  # Default key type when not specified in create_api_key!
  # When set and key_types is configured, keys created without explicit
  # key_type will use this default.
  # Default: nil (must specify key_type explicitly when key_types is configured)
  #
  # config.default_key_type = :secret

  # ============================================================================
  # KEY LIMITS & BEHAVIORS
  # ============================================================================

  # Global limit on the number of *active* keys an owner can have.
  # Can be overridden per-model with `max_keys` in the `has_api_keys` block, like:
  #   has_api_keys max_keys: 5
  # Set to nil for no global limit.
  # Default: nil
  # config.default_max_keys_per_owner = 10

  # Require a name when creating keys.
  # Can be overridden per-model with `require_name` in the `has_api_keys` block.
  # Default: false
  # config.require_key_name = true

  # Automatically expire keys after a certain period from creation.
  # Set to nil for no automatic expiration.
  # Default: nil
  # config.expire_after = 90.days

  # Default scopes to assign to newly created keys if none are specified.
  # Can be overridden per-model with `default_scopes` in the `has_api_keys` block.
  # Default: []
  # config.default_scopes = ["read"]

  # ============================================================================
  # TOKEN GENERATION
  # ============================================================================
  #
  # The number of random bytes to generate for the token (before encoding).
  # More bytes = more entropy = harder to guess.
  # SECURITY: Minimum recommended is 16 bytes (128 bits). Default provides 192 bits.
  # Default: 24 (generates ~32 Base58 chars or 48 hex chars)
  # config.token_length = 24

  # The encoding alphabet for the random part of the token.
  #   :base58 - shorter tokens, avoids ambiguous chars (0, O, I, l) - RECOMMENDED
  #   :hex    - standard hexadecimal encoding, longer tokens
  # Default: :base58
  # config.token_alphabet = :base58

  # ============================================================================
  # STORAGE & VERIFICATION
  # ============================================================================

  # The hashing strategy used to store token digests in the database.
  #
  # :sha256 (RECOMMENDED for API keys)
  #   - Fast, performant, O(1) database lookups
  #   - Secure for high-entropy tokens (192+ bits from SecureRandom)
  #   - Industry standard for API keys (used by Stripe, GitHub, AWS)
  #
  # :bcrypt (for extra security at cost of performance)
  #   - Includes salt, computationally expensive by design
  #   - 10x-50x slower than SHA256 - impacts every API request
  #   - Better for low-entropy secrets (passwords), overkill for random API keys
  #
  # Default: :sha256
  # config.hash_strategy = :sha256

  # ============================================================================
  # SECURITY
  # ============================================================================

  # Log a warning if API authentication is attempted over HTTP in production.
  # API keys should always be transmitted over HTTPS.
  # Default: true
  # config.https_only_production = true

  # Raise an error (instead of just warning) for HTTP in production.
  # Only applies when https_only_production is true.
  # Default: false
  # config.https_strict_mode = false

  # ============================================================================
  # BACKGROUND JOBS & CALLBACKS
  # ============================================================================
  #
  # The gem can update usage statistics and execute callbacks asynchronously
  # using ActiveJob. For reliable operation, configure a persistent job backend
  # (Sidekiq, GoodJob, SolidQueue, etc.).
  #
  # WARNING: The default :async adapter may lose jobs on app restart.
  # The :inline adapter runs synchronously, impacting request performance.
  # ============================================================================

  # Master toggle for all background job operations.
  # When false, last_used_at, requests_count, and callbacks are NOT processed.
  # Default: true
  # config.enable_async_operations = true

  # Track request counts (increments requests_count on each authentication).
  # Note: High-frequency counter updates can impact database performance.
  # Default: false
  # config.track_requests_count = false

  # Queue names for background jobs.
  # Default: :default
  # config.stats_job_queue = :default
  # config.callbacks_job_queue = :default

  # Callbacks executed on authentication attempts.
  # before_authentication: receives the request object
  # after_authentication: receives the Result object (success/failure info)
  #
  # Default: empty procs (no-op)
  # config.before_authentication = ->(request) { Rails.logger.info "Auth: #{request.uuid}" }
  # config.after_authentication = ->(result) { Analytics.track(result) }

  # ============================================================================
  # PERFORMANCE
  # ============================================================================

  # Time-to-live (TTL) for caching API key lookups in Rails.cache.
  #
  # Higher values = better performance (fewer DB queries)
  # Lower values = faster propagation of revocations/changes
  #
  # Trade-off: A revoked key may still work for up to `cache_ttl` seconds
  # until the cache expires.
  #
  # Set to 0 or nil to disable caching entirely.
  # Default: 5.seconds
  # config.cache_ttl = 5.seconds

  # ============================================================================
  # DEBUGGING
  # ============================================================================

  # Enable verbose debug logging.
  # Default: false
  # config.debug_logging = false
end
