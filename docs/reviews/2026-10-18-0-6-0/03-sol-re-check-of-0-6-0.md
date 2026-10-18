# Re-check of the 0.6.0 fixes, round 3 (Codex Sol, 2026-10-18, at 497879e, PR #66)

Scope: `git diff fe28e9c..497879e`, the answer to review 02, read-only. Verdict: PASS; the two small items (a README sentence that still said every retrieval attempt uses the handoff up; two transaction-boundary tests that did not create the state they named) were applied in the next commit. Open by nature of the environment: PostgreSQL and MySQL races, and a browser test of switching the key type.

## Blocking

- **Durable handoff: closed for Active Record transactions.** The guard checks the **ApiKey pool’s current connection**, before either consumption write, regardless of cache. An unconsumed handoff returns `:inside_transaction` and is restored; a previously committed claim returns `:already_shown` and stays removed. Commit, rollback, cache replacement and cache-flush tests meaningfully exercise those paths. Cache replacement simulates another process; it does not launch one. [token_session.rb:186](lib/api_keys/helpers/token_session.rb:186), [token_session.rb:286](lib/api_keys/helpers/token_session.rb:286), [token_session_test.rb:353](test/helpers/token_session_test.rb:353), [token_session_test.rb:382](test/helpers/token_session_test.rb:382), [token_session_test.rb:499](test/helpers/token_session_test.rb:499)

- **Compatibility boundary: verified.** Without the column, or without a named key, transaction refusal is bypassed and the cache-only behavior remains. The unmigrated transaction test genuinely drops the column. Raw SQL `BEGIN` remains undetected; its test actually releases plaintext and then rolls back the claim. That limitation is now explicit. [token_session.rb:302](lib/api_keys/helpers/token_session.rb:302), [token_session_test.rb:484](test/helpers/token_session_test.rb:484), [token_session_test.rb:514](test/helpers/token_session_test.rb:514), [README.md:517](README.md:517)

## Should fix

- **Non-raising cache-write failures: closed.** Suppression requires both `written == false` and a present reservation. Nil, absent entries and exceptions enqueue. The added tests exercise nil writes, false writes without storage, and failing existence checks through both successful and refused authentication. Existing burst tests exercise genuine suppression before workers run. [authentication.rb:243](lib/api_keys/authentication.rb:243), [refusal_stats_test.rb:239](test/refusal_stats_test.rb:239), [refusal_stats_test.rb:303](test/refusal_stats_test.rb:303)

- **False enqueue results: closed with a working cache.** Both paths release reservations on false results and exceptions. The four-call expectation genuinely requires another attempt for each kind after its first false result. Cleanup remains best effort: a failed cache deletion can retain the reservation until expiry, because false deletion results are ignored and exceptions swallowed. The enqueue failure itself is logged. [authentication.rb:162](lib/api_keys/authentication.rb:162), [authentication.rb:198](lib/api_keys/authentication.rb:198), [authentication.rb:262](lib/api_keys/authentication.rb:262), [refusal_stats_test.rb:359](test/refusal_stats_test.rb:359)

- **Creation form: remains closed.** Server-side creation resolves the default type and replaces submitted ceiling scopes. The new test genuinely POSTs with **both type and scopes omitted**, then with omitted type and crafted scopes. [keys_controller.rb:79](app/controllers/api_keys/keys_controller.rb:79), [keys_controller_test.rb:826](test/controllers/keys_controller_test.rb:826)

- **Retrieval inspection: remains closed.** The test obtains plaintext successfully before checking string, inspection, nested inspection, pretty-print and JSON representations. [token_session_test.rb:782](test/helpers/token_session_test.rb:782)

- **Reconciliation eligibility: remains closed.** The new retyping test updates the database after selection and before `with_lock` reloads the stale object, then checks unchanged scopes and exclusion from the count. This is a meaningful controlled interleaving on one connection. [reconcile_scopes_test.rb:13](test/reconcile_scopes_test.rb:13), [reconcile_scopes_test.rb:62](test/reconcile_scopes_test.rb:62), [api_key.rb:650](lib/api_keys/models/api_key.rb:650)

## Nits

- **Solid Cache documentation: closed.** The stats section now distinguishes conditional writes from atomic absent-entry reservation and explicitly permits simultaneous extra jobs on Solid Cache/PostgreSQL. Cache failures still intentionally permit one job per request before timestamp persistence. [README.md:1162](README.md:1162), [CHANGELOG.md:26](CHANGELOG.md:26)

- **Transaction documentation: substantially closed.** README, SECURITY and CHANGELOG acknowledge host controller transactions and raw SQL boundaries; the filed disposition explicitly supersedes the earlier cache-dependent answer. One remaining inconsistency: “Any retrieval attempt uses the handoff up” contradicts the new retry-preserving status. Qualify it. [README.md:489](README.md:489), [SECURITY.md:49](SECURITY.md:49), [CHANGELOG.md:29](CHANGELOG.md:29), [review trace:36](docs/reviews/2026-10-18-0-6-0/01-astra-review-of-0-6-0.md:36)

- **Empty-scope wording: closed. Version bump: outstanding.** The ceiling exception remains explicit; the runtime version remains `0.5.1`. [README.md:890](README.md:890), [version.rb:4](lib/api_keys/version.rb:4)

## Missing tests

- **SQLite races: closed; PostgreSQL/MySQL coverage remains open.** Both races now hold distinct autocommit connections before opening the barrier and require exactly one `:retrieved` plus seven `:already_shown` results. The NullStore race also checks committed state and later replay. [token_session_test.rb:46](test/helpers/token_session_test.rb:46), [token_session_test.rb:77](test/helpers/token_session_test.rb:77), [token_session_test.rb:309](test/helpers/token_session_test.rb:309)

- **Transaction boundaries: partially closed.** Separate-pool and raw-SQL scenarios are real. However, the “non-joinable inner transaction” joins the existing joinable transaction because it omits `requires_new: true`. Also, on the inspected Rails 8.1.4 source, the untouched outer transaction lets the `requires_new` case use `RestartParentTransaction`, so it does not establish a physical savepoint. Add a real non-joinable transaction and dirty the outer transaction before testing a savepoint. The implementation’s `transaction_open?` check itself covers these states. [token_session_test.rb:433](test/helpers/token_session_test.rb:433), [token_session_test.rb:461](test/helpers/token_session_test.rb:461), [token_session_test.rb:465](test/helpers/token_session_test.rb:465), [database_statements.rb:372](rails source), [transaction.rb:538](rails source)

- **Original burst/bcrypt gaps: remain closed. Browser type switching: still unexecuted.** The rendering test inspects markup/configuration and server-rendered defaults; it never executes the change listener. [refusal_stats_test.rb:192](test/refusal_stats_test.rb:192), [refusal_stats_test.rb:239](test/refusal_stats_test.rb:239), [keys_controller_test.rb:774](test/controllers/keys_controller_test.rb:774)

VERDICT: PASS

The round-2 release blockers are closed under the documented Active Record transaction boundary. I found no new blocking defect across the complete five-commit delta. The remaining documentation and coverage gaps are nonblocking; bump the version before publishing 0.6.0. This was a static review: no tests executed or repository changes made. Both requested `.cursor/rules` files remain absent.