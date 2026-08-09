## [Unreleased]

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

### Reliability

- Execute authentication callbacks exactly once with serializable, credential-free context hashes.
- Resolve job queues dynamically, prevent out-of-order/future jobs from corrupting usage timestamps, and keep request counters atomic.
- Validate security-sensitive global and per-owner configuration early and store permission policy as defensive frozen copies.
- Ensure each appraisal excludes the next Rails line's prereleases; Rails 7.2 uses its upstream-compatible Minitest 5 while Rails 8/default suites remain on Minitest 6.

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
