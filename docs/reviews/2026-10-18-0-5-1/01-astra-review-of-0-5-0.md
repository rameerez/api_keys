# Adversarial security review of api_keys 0.5.0 (Codex Astra, 2026-10-18, at main ab6cc19)

Scope: `lib/`, the dashboard under `app/`, generators and migration templates, SECURITY.md and the README's security claims, read-only, against the threat model in the prompt (an unauthenticated client, a low-privilege or other-tenant key holder, a timing observer, a misconfigured host app). Verdict: BLOCK; every finding below was answered in 0.5.1 (PR #64), see 02 and 03.

Reviewed `ab6cc19` read-only, including all requested source files. Confirmed the principal edge cases with isolated, in-memory Ruby checks; did not run the full suite.

## Blocking

1. **IP restrictions are bypassable when Rails is directly reachable without a sanitizing proxy.** The default resolver trusts `request.remote_ip` ([configuration.rb:597](lib/api_keys/configuration.rb:597)), and authentication accepts its result ([authenticator.rb:479](lib/api_keys/services/authenticator.rb:479)).

   **Attack:** Hold a valid key restricted to `203.0.113.7`; connect from a disallowed address; send `X-Forwarded-For: 203.0.113.7`. In the reproduction, adding that header changed authentication from `ip_not_allowed` to success. This is deployment-dependent and falls within the stated misconfiguration threat model. Rails explicitly documents this behavior in [RemoteIp](https://api.rubyonrails.org/classes/ActionDispatch/RemoteIp.html).

   **Fix:** Document and test direct-server deployments explicitly. Without a proxy, resolve the socket peer or strip forwarding headers before Rails. Behind a proxy, prevent direct access and sanitize forwarding headers; configuring `trusted_proxies` alone does not establish that boundary.

2. **Clearing every dashboard scope silently preserves permissions.** Both checkbox groups suppress unchecked values ([form:77](app/views/api_keys/keys/_form.html.erb:77), [form:111](app/views/api_keys/keys/_form.html.erb:111)). Consequently, clearing everything submits no `scopes` parameter. Updating leaves existing scopes untouched ([keys_controller.rb:103](app/controllers/api_keys/keys_controller.rb:103)); creation substitutes default scopes ([has_api_keys.rb:283](lib/api_keys/models/concerns/has_api_keys.rb:283)).

   **Attack:** A client holds a read-scoped key. Its owner unchecks every permission and saves successfully. The client continues accessing read-protected endpoints. Creating a supposedly permissionless key similarly grants defaults.

   **Fix:** Submit an explicit empty-array sentinel and normalize it to `[]`. Test the actual rendered form submission.

## Should fix

- **Malformed restriction values can become unrestricted.** `filter_map` drops `false` and `nil` rather than preserving them for validation ([restrictions.rb:140](lib/api_keys/restrictions.rb:140), [restrictions.rb:205](lib/api_keys/restrictions.rb:205)). Verified that `{"ips":false}`, `{"ips":[false]}`, and `{"ips":[null]}` become unrestricted; `key.update!(allowed_ips: false)` persists `{}`. The same applies to origins. This contradicts [CHANGELOG.md:21](CHANGELOG.md:21). Preserve invalid entries and reject them; distinguish an intentionally empty list from malformed data.

- **Policy changes can prevent revocation of an active key.** `revoke!` performs a fully validated update ([api_key.rb:215](lib/api_keys/models/api_key.rb:215)). After reducing a ceiling from `read,write` to `read`, an existing `read,write` key fails revocation validation ([api_key.rb:652](lib/api_keys/models/api_key.rb:652)) while remaining active and authorized for `read` ([api_key.rb:349](lib/api_keys/models/api_key.rb:349)). Confirmed in memory. Make revocation an atomic operation independent of unrelated validations, retaining the explicit revocability guard.

- **The token handoff is replayable, despite the one-time claim.** Retrieval only deletes the payload from the supplied session ([token_session.rb:89](lib/api_keys/helpers/token_session.rb:89)). Replaying a pre-consumption CookieStore cookie—or making concurrent requests with it—can recover the same token during its ten-minute lifetime. A copied-session reproduction returned the token twice. This contradicts the reused-handoff guarantee at [README.md:473](README.md:473); it does not bypass dashboard ownership. Use an atomic server-side consume operation for a genuine one-time guarantee, or qualify the documentation.

- **Header parsing precedes encoding and size validation.** The Bearer regex executes at [authenticator.rb:129](lib/api_keys/services/authenticator.rb:129), before the checks at [authenticator.rb:345](lib/api_keys/services/authenticator.rb:345). An invalid UTF-8 header string raises an uncaught `ArgumentError`; oversized headers are scanned before rejection. Validate the raw header first and return a controlled credential failure. Internet reachability of the encoding case depends on the server/middleware’s string handling.

## Nits

- The dashboard security page says publishable keys cannot be revoked individually ([best_practices:27](app/views/api_keys/security/best_practices.html.erb:27)), although revocability defaults to true ([api_key.rb:402](lib/api_keys/models/api_key.rb:402)).
- The prefix table still promises untyped creation when key types are configured ([README.md:942](README.md:942)); creation now requires a supplied or default type ([has_api_keys.rb:257](lib/api_keys/models/concerns/has_api_keys.rb:257)).

## Missing tests

- **Real proxy resolution:** restriction tests supply an already-resolved fake `remote_ip`, missing forwarding-header spoofing and proxy-chain behavior ([request_restrictions_test.rb:12](test/request_restrictions_test.rb:12)).
- **Dashboard abuse:** actual all-unchecked form submissions; CSRF rejection with protection enabled; cross-owner update/revoke attempts. Current tests disable CSRF and exercise cross-owner show only ([keys_controller_test.rb:50](test/controllers/keys_controller_test.rb:50), [keys_controller_test.rb:330](test/controllers/keys_controller_test.rb:330)).
- **Malformed restriction matrices:** false/null scalars and array members. Existing non-string tests use integers ([restrictions_test.rb:344](test/restrictions_test.rb:344)).
- **Handoff replay/concurrency and browser history restoration:** current retrieval tests mutate one Hash ([token_session_test.rb:61](test/helpers/token_session_test.rb:61)).
- **Revocation after ceiling changes and malformed header encodings:** existing tests cover ordinary revocation and oversized tokens separately ([api_key_test.rb:486](test/models/api_key_test.rb:486), [authenticator_test.rb:272](test/services/authenticator_test.rb:272)).
- **Production database behavior:** quota concurrency, generated constraints, and authentication-index execution on PostgreSQL/MySQL. The suite uses an independently defined in-memory SQLite schema ([test_helper.rb:51](test/test_helper.rb:51)).

## Blue team

- **Enforce tenant and role authorization yourself.** Tenant resolution returns an object or `nil`; it does not compare against a requested tenant ([tenant_resolution.rb:26](lib/api_keys/tenant_resolution.rb:26)). Every dashboard owner can select every configured key type ([form:23](app/views/api_keys/keys/_form.html.erb:23)). Gate dashboard membership and type issuance appropriately, and scope resource queries to the authenticated owner.
- **Treat origins as browser-context restrictions.** Non-browser clients can forge them, as acknowledged at [README.md:1409](README.md:1409). Public permissions must remain safe under arbitrary replay.
- **Rate-limit before authentication and queue insertion.** Bcrypt guesses matching a prefix/last-four bucket trigger expensive comparisons, exposing bucket existence through timing ([authenticator.rb:218](lib/api_keys/services/authenticator.rb:218)). Distinct revoked/expired responses identify already-known complete tokens, not their missing characters ([authenticator.rb:104](lib/api_keys/services/authenticator.rb:104)).
- **Do not use callbacks or counters as exactly-once business events.** Attempts enqueue callbacks; statistics debounce depends on a completed database update, so queue lag permits bursts. Duplicate job delivery increments counters again ([authentication.rb:154](lib/api_keys/authentication.rb:154), [authentication.rb:186](lib/api_keys/authentication.rb:186), [update_stats_job.rb:53](lib/api_keys/jobs/update_stats_job.rb:53)). Monitor queue depth and make consequential consumers idempotent.
- **Apply deployment controls independently:** TLS, protected sessions, credential filtering, and maintained dependencies. Installable dependency floors are broader than security support ([api_keys.gemspec:40](api_keys.gemspec:40), [SECURITY.md:7](SECURITY.md:7)); operational requirements are listed at [SECURITY.md:26](SECURITY.md:26).

VERDICT: BLOCK

The blocking concerns are authorization behavior at integration boundaries: spoofable client-IP resolution in an explicitly in-scope deployment and a dashboard action that silently fails to remove permissions. The malformed-policy, revocation, and handoff findings also weaken stated security guarantees. Address these with focused regression tests before treating 0.5.0 as ready under this threat model.