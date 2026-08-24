## [0.4.3] - 2026-08-24

- Republish of 0.4.2 with a clean package: the 0.4.2 gem shipped carrying a stray 200 KB `api_keys-0.4.1.gem` blob at its root (committed by accident during the release, harmless but dead weight). No code changes. Prefer this over 0.4.2.

## [0.4.2] - 2026-08-24

### Changed

- No library changes. Development-dependency and CI bumps (sqlite3 2.9.6 — clears GHSA-mwm8-39rw-8826 in the dummy app, thruster 0.1.25, brakeman 8.0.6, CodeQL and release-gem action pins).
- Release housekeeping: 0.4.1 shipped to RubyGems with the dashboard CSP fix, but its GitHub release page was lost to the repository's immutable-release rule during the cut and its tag points at a pre-squash commit (tree-identical to main). 0.4.2 consolidates: this tag is on main and this release page carries 0.4.1's notes below.

## [0.4.1] - 2026-08-24

### Fixed

- Stop the dashboard's Content Security Policy from blocking the host application's own stylesheets, scripts, and self-hosted webfonts. The 0.4.0 policy declared `default-src 'none'` with `script-src`/`style-src` reduced to the per-request nonce, but Rails only stamps that nonce onto `stylesheet_link_tag`/`javascript_include_tag` when the host application sets `content_security_policy_nonce_auto` (off by default, and not something an engine can enable for its host). Any application rendering its normal layout on engine pages got an unstyled, inert dashboard with no server-side error. The default policy now trusts same-origin scripts, styles, and fonts, adds `font-src`, and allows `https:` images, while keeping the nonce, `default-src 'self'`, `base-uri 'none'`, `object-src 'none'`, `frame-ancestors 'none'`, `frame-src 'none'`, `form-action 'self'`, and `connect-src 'self'`.
- Stop generated install and authentication-index migrations from carrying an unreachable `migration_version` instance method; the generator already renders the Active Record version into each migration superclass.

### Added

- `config.dashboard_content_security_policy` selects the policy the mounted dashboard declares: `:default` (new default, hardened but compatible with a normal host layout), `:strict` (the 0.4.0 nonce-only policy, unchanged), or `false`/`nil` to declare nothing and leave the host application's policy alone. The setting is resolved per request and validated on assignment.

### Upgrade notes

- Applications that relied on the 0.4.0 nonce-only dashboard policy should set `config.dashboard_content_security_policy = :strict` to keep it. That policy requires a layout that serves nothing un-nonced on engine pages; the gem's built-in layout satisfies it, and host layouts additionally need `config.content_security_policy_nonce_auto = true`.

### Maintenance

- Move SimpleCov startup/reporting into the test helper and replace deprecated filtering/tracking APIs so the enforced line and branch coverage gates remain compatible with future SimpleCov releases.

## [0.4.0] - 2026-08-09

This security-focused release hardens authentication, authorization, credential handling, the self-serve dashboard, background jobs, configuration, dependencies, CI, and the release supply chain. Upgrading is strongly recommended. Existing installations must apply the authentication lookup migration before deploying this version.

### Security

- Make token caching a non-authoritative ID lookup hint: every hit reloads current database state and cryptographically re-verifies the presented token, so revocation, expiration, scope changes, and cache poisoning fail closed.
- Replace token-derived SHA1 cache identifiers with SHA256 and prevent plaintext tokens, digests, stored public tokens, request objects, and authentication result objects from leaking through gem logs, inspection, serialization, errors, or async callback arguments.
- Bound token sizes, bcrypt input length, bcrypt cost, and bcrypt candidate work; add an indexed prefix/last-four/algorithm lookup for existing installations.
- Bound historical-prefix discovery and fall back to an indexed last-four lookup so cache poisoning or unusually many retired prefixes cannot create unbounded request work or strand valid bcrypt keys.
- Serialize all quota checks and inserts by locking the owner row, including direct Active Record creation paths.
- Enforce immutable authentication identity fields, supported digest formats, bounded scopes/metadata/identifiers/session payloads, runtime permission ceilings, configured key types, and fail-closed environment isolation.
- Require every newly created key to have a configured type once key-types mode is enabled; existing untyped legacy keys remain compatible.
- Require explicit finite permissions and `revocable: false` for intentionally stored public tokens.
- Fail closed when dashboard owner authentication is missing or ineffective; bind one-time session tokens to their created key; reject malformed create/update payloads; scope every dashboard lookup to the current owner; and add no-store, anti-framing, referrer, MIME-sniffing, and permissions headers.
- Apply an enforcing nonce-based dashboard Content Security Policy and remove inline handlers, un-nonced scripts, third-party assets, and inline style attributes from credential-bearing views.
- Enforce HTTPS authentication by default in production, disable query-string credentials in the demo, and remove third-party code from pages that handle tokens.
- Pin GitHub Actions to immutable commits and add dependency auditing, Brakeman, CodeQL, dependency review, and Dependabot configuration.
- Remove the unused Claude Code workflow and its third-party CI/OIDC surface.
- Encrypt one-time secret-token handoffs inside the Rails session with an application-derived AES-256-GCM key, bind them to the created key, expire them after ten minutes, and delete them on first retrieval. Legacy in-flight plaintext handoffs remain readable for upgrade continuity but are never newly written.

### Reliability

- Execute authentication callbacks exactly once with serializable, credential-free context hashes.
- Resolve job queues dynamically, prevent out-of-order/future jobs from corrupting usage timestamps, and keep request counters atomic.
- Validate security-sensitive global and per-owner configuration early and store permission policy as defensive frozen copies.
- Ensure each appraisal excludes the next Rails line's prereleases; Rails 7.2 uses its upstream-compatible Minitest 5 while Rails 8/default suites remain on Minitest 6.
- Return `403 Forbidden` when a valid key lacks a required scope while retaining `401 Unauthorized` for missing or invalid credentials.
- Honor the public `parent_controller` configuration (with a backward-compatible internal Engine fallback), cascade owner deletion across non-revocable keys, and debounce `last_used_at` jobs for one minute by default when exact request counting is disabled.
- Remove redundant single-column polymorphic-owner indexes from new-install migrations and exclude development-only metadata from built gems.
- Resolve every finding recorded in [issue #12](https://github.com/rameerez/api_keys/issues/12) through a code fix, test, explicit bounded design, or superseding hardening control.

### Upgrade notes

- Existing installations should run `rails generate api_keys:add_authentication_index` and `rails db:migrate` before deploying this version.
- Invalid expiration presets now raise `ArgumentError` instead of silently creating a key without expiration.
- Authentication identity fields (`token_digest`, algorithm, prefix, last four, owner, key type, and environment) can no longer be changed through normal Active Record updates after creation.
- Typed keys with blank or retired environments now fail closed. Repair any such legacy rows before deployment; untyped legacy keys are unaffected.
- When `key_types` is configured, new keys must pass `key_type:` or use a configured `default_key_type`; this does not invalidate existing untyped keys.
- Authentication callbacks now execute asynchronously exactly once with small, credential-free context hashes instead of request, result, or model objects. Update callback consumers and ensure the application has a durable Active Job backend where delivery matters.
- Production authentication now requires HTTPS by default and fails closed when a request appears insecure. Verify TLS termination and trusted proxy forwarding before deployment.
- Scope and permission policy is enforced at creation, update, and authentication time. Malformed scopes and scopes above a configured ceiling are rejected; blank scopes deny access whenever a scope policy is enabled.
- Reassess every permission ceiling configured with `public: true`. The gem validates that public tokens are non-revocable and finitely scoped, but only the host application can determine whether each named permission is safe for an untrusted client.
- The actively security-tested matrix is Ruby 3.3, 3.4, and 4.0 with Rails 7.2, 8.0, and 8.1. The gemspec continues to permit Ruby 3.1+ for compatibility, but older runtimes are outside the documented security-support matrix.
- Missing-scope responses now use HTTP 403 instead of 401. Clients that branch on the previous status should update.
- New one-time token handoffs are encrypted and expire after ten minutes. Custom integrations must use `ApiKeys::TokenSession` rather than reading its internal session payload directly.
- `last_used_at` updates are debounced for one minute by default when `track_requests_count` is false. Set `stats_update_interval = 0` for per-request timestamps; enabling exact request counting necessarily enqueues a stats job for every successful authentication.
- Deleting an owner now removes all associated API-key rows, including non-revocable types. Direct user-level `revoke!`, `destroy`, and `destroy!` protections remain unchanged.

## [0.3.0] - 2026-02-09

- Add Stripe-style key types and environments (publishable/secret keys with test/live isolation)
- Add public key token storage for non-revocable publishable keys
- Add headless helpers for custom dashboard integrations
- Add usage analytics scopes for admin dashboards
- Fix PostgreSQL FOR UPDATE with COUNT aggregate error
- Fix blank scopes bypass in key_types mode: empty scopes no longer grant unrestricted access when permission ceilings are configured

## [0.2.1] - 2025-08-04

- Fix SecurityController callback reference from :authenticate_api_keys_user! to :authenticate_api_keys_owner!
- Resolves ArgumentError in production environments with eager loading (#2)

## [0.2.0] - 2025-06-03

- Make gem owner-agnostic: API keys can now belong to any model (User, Organization, Team, etc.)
- Add flexible dashboard configuration for custom owner models
- Add support for multi-tenant and team-based API key ownership
- Improve documentation with common ownership scenarios
- Add configuration options for current_owner_method and authenticate_owner_method

## [0.1.0] - 2025-04-30

- Initial release
