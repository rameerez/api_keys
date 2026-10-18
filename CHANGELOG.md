## [0.6.0] - Unreleased

### Added

- Ceiling-authoritative scopes, opt-in per key type ([#28](https://github.com/rameerez/api_keys/issues/28)). `key_types[...][:scopes] = :ceiling` makes the type's live `permissions:` list the contract for every key of that type, so widening it reaches existing keys and narrowing it takes effect on the next request. Every scope check consults it (`authenticate_api_key!(scope:)`, `allows_scope?`, `allows_permission?`); stored `scopes` stay as metadata. Requires a finite, non-empty `permissions` list. `ApiKey#scopes_follow_ceiling?` reports it, and the dashboard shows these keys' live permissions instead of scope checkboxes that would change nothing.
- `ApiKeys.reconcile_scopes!(key_type:)`: an add-only backfill that merges a type's current ceiling into the stored scopes of its non-revoked keys, for types that keep stored scopes after their ceiling was widened. Each key is rechecked under its row lock, so a key revoked while the backfill runs is skipped.
- Refused-but-identified traffic ([#38](https://github.com/rameerez/api_keys/issues/38)). `last_refused_at`, `refusals_count`, and `last_refusal_code` on `api_keys`, stamped through the same async `UpdateStatsJob` path as `last_used_at` whenever a request presents a key's real token and a policy refuses it: revoked, expired, type/environment configuration, environment isolation, origin/IP restrictions, and missing scope. The dashboard's key page says "Requests are arriving but refused: last at X, because Y", and the key list shows the latest refusal under "Last Used". `refusals_count` follows `track_requests_count`, like `requests_count`.
- Durable one-time token handoff (promised in 0.5.1). A `token_shown_at` column on `api_keys`, claimed by the first retrieval of a key's token through `ApiKeys::TokenSession` with one conditional `UPDATE ... WHERE id = ? AND token_shown_at IS NULL`. The claim is durable when retrieval runs outside a database transaction, as the dashboard's does. `ApiKey#token_shown_at` and `#token_shown?` report it.
- `ApiKeys::TokenSession.retrieve_once_with_status` consumes a handoff exactly like `retrieve_once` and also says why no token came back (`:already_shown`, `:withheld`, `:inside_transaction`, `:missing`). The dashboard's token page uses it: a replayed copy of the session, or a refresh after the token was shown, now says the token was already shown. Its `inspect`, `to_s`, pretty-print and JSON forms redact the token, like the authentication result's.
- `rails generate api_keys:add_key_activity` for existing installations: one idempotent migration with every 0.6.0 column (`last_refused_at`, `refusals_count`, `last_refusal_code`, `token_shown_at`). New installs create the columns from the start.
- `ApiKeys::ViewHelpers#api_key_refusal_reason` explains a key's latest refusal for custom dashboards.
- `ApiKey#scopes_after_form_edit(offered:, checked:)`: the dashboard's 0.5.1 edit rule as a public method for host forms built with `api_key_scopes_checkboxes`. Offered scopes follow their boxes, every other held scope is kept, an unoffered submitted value is ignored, and held scopes outside the current ceiling are dropped; a `scopes: :ceiling` key gets its stored scopes back unchanged. The dashboard now calls it.

### Changed

- `ApiKeys::Jobs::UpdateStatsJob#perform` takes an optional `refusal_code:` keyword. Jobs enqueued by earlier versions run unchanged. A job carrying any refusal marker, recognized or not, never touches `last_used_at` or `requests_count`.
- The scope-ceiling validation no longer blocks saving an existing `scopes: :ceiling` key whose stored scopes exceed a narrowed ceiling, as long as the scopes themselves are not being written. Those stored scopes authorize nothing, and the validation would otherwise stop owners from renaming the key or tightening its request restrictions.
- Dashboard edits of a `scopes: :ceiling` key never write its stored scopes. The form shows the type's live permissions with no scope boxes, the update ignores any submitted scopes, and stored scopes above a narrowed ceiling are kept as metadata rather than dropped. Every other key type keeps 0.5.1's rules: the form edits only the scopes it offers, keeps the rest, and drops held scopes outside the current ceiling.
- The dashboard's creation form hides and disables the scope boxes when a `scopes: :ceiling` type is selected and shows that type's live permissions instead, so an owner can no longer clear every box and still get a key with the whole ceiling. A create for such a type ignores any submitted scopes and stores the type's current ceiling as the key's metadata.

### Security

- `scopes: :ceiling` widens nothing it was not asked to. Types that do not opt in, untyped keys, and keys whose type is no longer configured keep their exact previous behavior. `:ceiling` against `permissions: :all` or an empty list is rejected when the configuration loads, and ignored at authorization time should a configuration bypass that validation. Damaged stored scopes on a ceiling key deny every scope.
- A refusal is never a use: refused traffic cannot move `last_used_at` or `requests_count`, so integrations that detect a first working request from `last_used_at` stay correct.
- Refusal statistics are written only after the presented token is verified, only for an allowlist of policy refusal codes, and debounced exactly like `last_used_at`. They add no unauthenticated write path.
- Stats jobs, for successful and for refused requests, are now deduplicated before a worker runs. The debounce read only the persisted timestamp, so N requests arriving before the first job ran enqueued N jobs. With a shared `Rails.cache`, the first request in a `stats_update_interval` reserves the enqueue for its key and kind with an atomic `write(..., unless_exist: true, expires_in: interval)` and the rest of the burst is skipped; a reservation whose job fails to enqueue is released. Exact counting (`track_requests_count`) is never deduplicated. Remaining limitation: with `NullStore`, no cache, or a cache error, only the persisted timestamp debounces, and such a burst still enqueues one job per request.
- The dashboard explains a refusal with fixed sentences and never renders the stored code itself.
- The one-time token handoff no longer depends on the cache keeping its marker. 0.5.1 recorded consumption only in `Rails.cache`, so a cache flush, restart, or eviction within the ten-minute handoff lifetime let a copy of the session taken before retrieval recover the token again. With `token_shown_at`, a retrieval outside a database transaction (the dashboard's) commits its claim before the token is returned, so the database admits exactly one retrieval per key, whatever happens to the cache and with any cache store, including `NullStore`. The cache marker stays as a second layer, made after the durable claim. Zero rows claimed (already shown, or the key no longer exists) and any database or cache error withhold the token. The model marks `token_shown_at` read-only, so no form or `update` can clear it and reopen a handoff. Without the column the handoff behaves exactly as in 0.5.1.
- Inside an open database transaction the claim is not durable: a rollback after the token was returned would undo it. There the cache marker is the only protection. With a shared cache the token is released and the marker refuses replays while it lasts; after a rollback, losing the marker re-opens replay. With no shared cache the token is withheld as `:inside_transaction`, nothing is recorded, and the handoff stays in the session for a retrieval outside the transaction.

### Upgrade notes

- Run `rails generate api_keys:add_key_activity` and `rails db:migrate` to start recording refusals and make the token handoff durable. Until then, authentication is unchanged, refusals are not recorded, and the handoff relies on the cache marker alone, as in 0.5.1. Migrate before deploying the code, or deploy and then migrate: both orders are safe, and a process started before the migration picks up the columns when it restarts.
- Each key's token can now be handed off once, ever. A host that stores two handoffs for the same key (for example under two session keys) gets the token from the first retrieval only.
- Deploy job workers together with web processes. A refusal job enqueued by 0.6.0 errors on a 0.5.x worker, whose `perform` takes no keyword; depending on your backend it is retried or dropped, and it is never recorded as a use.
- If you have widened a key type's `permissions:` since its keys were created, those keys still carry the old list. Opt the type into `scopes: :ceiling` when its users do not curate scopes, or run `ApiKeys.reconcile_scopes!(key_type: ...)`. See the README section "Widening a ceiling does not reach existing keys".

## [0.5.1] - 2026-10-18

### Security

- Clearing every permission in the dashboard now removes the key's scopes. With every box unchecked the form submitted no `scopes` parameter, so an update kept the old scopes and a create applied the default scopes. Both checkbox groups now render an empty `api_key[scopes][]` sentinel: an empty selection means "no scopes" and the model's validations decide, while defaults still apply when the parameter is absent. The edit form changes only the scopes it offers (the owner's default scopes) and keeps every other scope a key holds, so a rename no longer strips a scope the form never showed. A failed create re-renders the boxes as submitted instead of re-checking all of them.
- `FormBuilderExtensions#api_key_scopes_checkboxes` renders the same sentinel before the boxes when a block is given. Host forms will see one extra hidden input. By default it is rendered only when there is at least one box and the form's key enforces its scopes (new `ApiKey#scopes_enforced?`), because where scopes are not enforced an empty list still means "unrestricted". Per-owner default scopes are read through the key's owner, so a form with no object or on a bare `ApiKey.new` renders no sentinel unless you pass `include_hidden: true`; build the key with `owner.api_keys.build`. `include_hidden: false` turns it off.
- `ApiKey#revoke!` no longer depends on unrelated validations. A key issued before its type's permission or restriction ceiling was narrowed kept authenticating but could not be revoked. Revocation keeps the revocability guard and the save callbacks, writes only `revoked_at` (and `updated_at`), and still validates any other unsaved edits on the same instance. The next request is refused as `revoked_key`, including through the token cache.
- Malformed restriction values fail closed. Coercion dropped `false`, `nil`, and blank entries, so stored `{"ips": false}`, `{"ips": [false]}`, or `{"ips": [null]}` read as unrestricted and `update!(allowed_ips: false)` stored `{}`; the same applied to origins. Such values are now kept, rejected by validation, and refuse authentication with `restriction_misconfigured` when found in the database; a stored `null` or blank kind is refused too. Input keeps its 0.5.0 meaning where it was unambiguous: a kind given as `nil` or blank text to `restrictions=`, `create_api_key!(restrictions:)`, or the `allowed_origins=` / `allowed_ips=` writers clears that list, so `create_api_key!(restrictions: { ips: nil })` still creates an unrestricted key. `false`, wrong types, and `null` or blank members inside a list are rejected on input. A malformed `restrictions:` argument to `create_api_key!` now reaches validation instead of being normalized to `{}`. The dashboard shows a stored policy's malformed entries instead of empty fields and leaves an untouched field's list as stored, so a rename can no longer turn a malformed policy into an unrestricted one; the save is refused until the owner corrects it.
- The authentication header is checked for encoding and size before it is parsed. An invalid UTF-8 header raised `ArgumentError` from the Bearer match; it now answers `invalid_token`, and a header longer than the token limit plus 64 bytes is refused without being scanned.
- The one-time token handoff is now one-time across copies of the session. Retrieval deleted the payload only from the session it was given, so a copied pre-retrieval cookie, or two concurrent requests, could recover the token twice within its ten-minute lifetime. Each handoff now carries a random ID, and the first retrieval records it with an atomic `Rails.cache.write(..., unless_exist: true)`; later retrievals get `nil` while the cache keeps that record, and a cache error withholds the token. The guarantee needs both a shared store with atomic `unless_exist:` and retention of the record for the ten-minute handoff lifetime: if the cache is flushed, restarted, or evicts the record within that window, a copied pre-retrieval cookie recovers the token again. Durable consumption state is planned for 0.6.0. With `ActiveSupport::Cache::NullStore` or no cache, the session deletion remains the only protection. With Solid Cache on PostgreSQL, two simultaneous first retrievals can both succeed; sequential replays are stopped. The handoff format is unchanged, so 0.5.0 and 0.5.1 processes can read each other's handoffs during a rolling deploy.
- IP restrictions: the README, SECURITY.md, the generated initializer, and the `add_restrictions` generator now state that the default `request.remote_ip` resolver trusts `X-Forwarded-For`. Behind a proxy that is the only way in, keep it; when the Rails server is directly reachable, use `->(request) { request.remote_addr }`. `trusted_proxies` alone is not a boundary. The suite covers both shapes through Rails' `ActionDispatch::RemoteIp`. The default is unchanged.

### Fixed

- The dashboard's security page no longer says publishable keys cannot be revoked individually; since 0.5.0 they can, unless their key type sets `revocable: false`.
- The README's prefix table no longer says a key can be created without a type when key types are configured. Such a key takes `default_key_type`, or creation raises.

## [0.5.0] - 2026-08-25

### Added

- Request restrictions: per-key `allowed_origins` (exact hosts and `*.subdomain` wildcards, matched against the browser's Origin with Referer fallback) and `allowed_ips` (IPv4/IPv6, exact or CIDR). Enforced inside `Authenticator.call` for every key on every request, including token-cache hits, so no controller can forget to check and a tightened allowlist takes effect on the next call. Failures answer 403 with `origin_not_allowed` / `ip_not_allowed`. Empty restrictions mean unrestricted, so existing keys are unaffected.
- `ApiKeys::Restrictions` value object: normalization, matching, and the forgiving parsers dashboards want (`.normalize_origins`, `.normalize_ips`, `.extract_origin_host`). Host applications can delete their own origin parsers.
- Per-key-type restriction ceilings via `key_types[...][:restrictions]`, mirroring the way `permissions:` caps scopes. Omitted allows both kinds; `[]` forbids restrictions for that type.
- `config.client_ip_resolver` (defaults to `request.remote_ip`, which honors Rails' trusted proxies).
- `rails generate api_keys:add_restrictions` for existing installations; new installs create the column from the start.
- Dashboard: origin and IP fields on the key form (shown dynamically per the selected key type's ceiling), expiration only for expirable key types, preserved form values after errors, and a "Restricted" badge.
- Model surface: `restrictions`, `restricted?`, `allowed_origins`/`allowed_ips` readers and raw-string writers, `restricted`/`unrestricted` scopes, and `create_api_key!(restrictions:, allowed_origins:, allowed_ips:)`.
- Refusal attribution: every failure after a key has been identified (revoked, expired, type/environment configuration, isolation, and request restrictions) carries its `api_key_id`; lookup failures do not.

### Changed

- `public: true` is now independent of `revocable:`. Public key types remain subject to a finite non-empty permission ceiling, but can use the normal rotation, revocation, deletion, and expiration lifecycle.

### Security

- Restriction failures never echo the configured allowlist back to the caller.
- Every restriction failure mode fails closed: a locked list plus an unreadable origin, an unresolvable client IP, an unknown kind, a scalar policy, or an unparseable stored entry refuses the request. Generated migrations add a database check that the policy is a JSON object where the adapter supports it.

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
