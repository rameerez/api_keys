# Re-review of the 0.5.1 fixes (Codex Astra, 2026-10-18, at f247984, PR #64)

Scope: `git diff fd598aa..f247984`, the answer to review 01, read-only. Verdict: BLOCK only on the handoff guarantee being overstated (the consumption marker lives in the cache, so cache loss within the handoff lifetime re-opens replay for a copied cookie), plus one documentation nit; both were applied in the next commit (wording in README, SECURITY.md and the CHANGELOG; a test that pins the cache-loss replay; the blank-member sentence qualified). Durable consumption state is planned for 0.6.0. Every original attack is closed; the client-IP finding is closed by documentation and tests of the deployment shapes, with the default unchanged.

## Blocking

**Scope:** The requested checkout remains at `fd598aa`; its diff is empty. I reviewed the available candidate `fd598aa..f247984` in `/Users/javi/GitHub/api_keys-security` instead. This was code inspection only; “would fail on 0.5.0” below is a static assessment.

- **IP spoofing: documented mitigation, unchanged default.** The real middleware tests perform the original attack and explicitly expect spoofed authentication to succeed; the socket-peer and proxy-chain tests verify the documented deployment configurations. These tests would also pass on 0.5.0: they establish deployment requirements, not changed protection. This satisfies the requested documentation/test remedy, but directly reachable installations must apply it. No new runtime behavior. [request_restrictions_test.rb:852](test/request_restrictions_test.rb:852)

- **All-unchecked dashboard scopes: closed.** Tests serialize the rendered form after removing every checkbox’s checked attribute, submit it, and verify permissions disappear on creation and update. Both would fail on 0.5.0. Updates now preserve scopes outside the displayed choices and ignore submitted additions outside those choices; the form explicitly identifies retained scopes. [keys_controller_test.rb:357](test/controllers/keys_controller_test.rb:357), [keys_controller.rb:181](app/controllers/api_keys/keys_controller.rb:181), [_form.html.erb:118](app/views/api_keys/keys/_form.html.erb:118)

## Should fix

- **Malformed restrictions: original attacks closed.** False/null members survive coercion and fail validation; stored malformed values refuse authentication. Tests exercise both stored corruption and writer updates, including the original false/null cases, and would fail on 0.5.0. Scalar `nil` remains an intentional clearing operation on input. Untouched malformed dashboard fields retain their stored meaning instead of becoming unrestricted. [restrictions.rb:232](lib/api_keys/restrictions.rb:232), [request_restrictions_test.rb:698](test/request_restrictions_test.rb:698), [keys_controller.rb:214](app/controllers/api_keys/keys_controller.rb:214)

- **Revocation after policy changes: closed for clean loaded records.** The tests narrow an issued key’s ceiling, establish that validation fails, then revoke it—including through a warm authentication cache. They would fail on 0.5.0. The revocability guard and save callbacks remain; instances carrying other pending edits still validate and can fail revocation. That limitation is explicit and tested, rather than silently saving those edits unvalidated. [api_key.rb:232](lib/api_keys/models/api_key.rb:232), [authenticator_test.rb:319](test/services/authenticator_test.rb:319), [api_key_test.rb:553](test/models/api_key_test.rb:553)

- **Handoff replay: improved, but the guarantee remains overstated.** Copied-session and threaded tests perform the attack and would fail on 0.5.0. However, consumption exists only as a cache marker: consume once, clear the cache, then replay the still-valid copied session, and the write succeeds again. Shared, atomic storage alone therefore does not establish the README’s “at most once” guarantee; marker retention is also required. Document cache-loss replay or use durable consumption state. Cache failure now withholds the token—a deliberate availability change. [token_session.rb:202](lib/api_keys/helpers/token_session.rb:202), [token_session_test.rb:215](test/helpers/token_session_test.rb:215), [README.md:481](README.md:481)

- **Header parsing: original attacks closed.** Raw size/encoding checks precede the regex. Tests supply invalid UTF-8 and explicitly forbid matching an oversized header; both would fail on 0.5.0. The new compatibility boundary is a 576-byte complete header limit, including Bearer whitespace. [authenticator.rb:138](lib/api_keys/services/authenticator.rb:138), [authenticator_test.rb:350](test/services/authenticator_test.rb:350)

## Nits

- Both previous documentation errors are corrected. [best_practices.html.erb:27](app/views/api_keys/security/best_practices.html.erb:27), [README.md:961](README.md:961)
- The new claim that blank array members fail validation is too broad: the writer test explicitly accepts `allowed_ips: [""]` and clears restrictions. Qualify the input-path distinction. [README.md:1386](README.md:1386), [request_restrictions_test.rb:768](test/request_restrictions_test.rb:768)

## Missing tests

- Add consumption-marker loss followed by replay. Current concurrency coverage uses one process and `MemoryStore`, not a production shared backend. [token_session_test.rb:225](test/helpers/token_session_test.rb:225)
- CSRF rejection and cross-owner writes are now meaningfully covered; these establish existing protections and should pass on 0.5.0. Browser-history restoration remains uncovered by the controller replay test. [keys_controller_test.rb:562](test/controllers/keys_controller_test.rb:562), [keys_controller_test.rb:596](test/controllers/keys_controller_test.rb:596), [keys_controller_test.rb:638](test/controllers/keys_controller_test.rb:638)
- PostgreSQL/MySQL concurrency, migration constraints, and index execution remain unverified; the suite still defines an in-memory SQLite schema. [test_helper.rb:51](test/test_helper.rb:51)

VERDICT: BLOCK

The candidate substantially addresses the original review, but I would correct the remaining handoff guarantee and add cache-loss replay coverage before publishing it as the security-fix release. The documented IP configuration remains mandatory. This assessment covers `f247984`, not the requested merged `main`, which currently contains none of these fixes.