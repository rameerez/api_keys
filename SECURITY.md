# Security Policy

`api_keys` handles authentication credentials. Please report suspected vulnerabilities privately and avoid including real API keys, production data, or customer information in any report.

## Supported versions

Security fixes are released for the latest published version. The maintained test matrix covers Ruby 3.3, 3.4, and 4.0 with patched Rails 7.2, 8.0, and 8.1 releases. Older Ruby and Rails versions may remain installable for compatibility, but runtimes that no longer receive upstream security fixes are not security-supported.

## Reporting a vulnerability

Use GitHub's **Report a vulnerability** button on the [`api_keys` security advisories page](https://github.com/rameerez/api_keys/security/advisories) so the report and any proposed fix remain private. If GitHub's private reporting flow is unavailable, email `rubygems@rameerez.com` with the subject `api_keys security report`.

Include:

- the affected version and environment;
- a minimal reproduction or proof of concept;
- the impact you believe is possible; and
- any suggested mitigation or patch.

Do not open a public issue for an undisclosed vulnerability. We will acknowledge the report, investigate it, and coordinate disclosure and credit with you. If the issue affects downstream applications, we will prioritize a patched release and clear upgrade guidance.

## Operational security

Applications remain responsible for:

- trusted TLS/proxy configuration, including a `client_ip_resolver` that matches how clients reach the Rails server (see below), endpoint authorization, and request rate limiting;
- encrypted, `Secure`, `HttpOnly`, appropriately `SameSite` session cookies for the one-time dashboard token handoff, and the 0.6.0 `token_shown_at` column (or, until it is migrated, a shared cache store) if that handoff must be one-time across copies of a session (see below);
- database, cache, queue, log, backup, and observability access controls;
- filtering any query-parameter credential name from application and proxy logs if that opt-in transport is enabled;
- classifying every permission on a `public: true` key type as safe for an untrusted public client and maintaining a disable/replacement procedure for non-revocable identifiers; and
- prompt dependency/runtime patching and a durable background-job backend where callbacks or usage statistics are required.

The gem bounds authentication work, but applications should still rate-limit credential endpoints. Do not treat a key prefix, last four characters, cache entry, or public key as proof of authorization.

### Client IP restrictions depend on your deployment

`allowed_ips` is checked against `config.client_ip_resolver`, which defaults to `request.remote_ip`. Rails derives that value from `X-Forwarded-For`, so it is only truthful in one of two shapes:

- **Behind a proxy that is the only way in.** The proxy overwrites `X-Forwarded-For` or appends the address it saw, and its addresses are covered by `config.action_dispatch.trusted_proxies`. Keep the default resolver.
- **Directly reachable.** If clients can connect to the Rails server itself, a client can send `X-Forwarded-For: <an allowed address>` and pass the check. Set `config.client_ip_resolver = ->(request) { request.remote_addr }` so the socket peer is checked.

Configuring `trusted_proxies` alone is not a boundary: it tells Rails which hops to skip, and does nothing about a client that bypasses the proxy. Block that path at the network layer or use the socket-peer resolver. The gem does not change the default, because the right answer depends on a network it cannot see.

### What the one-time token handoff guarantees

The dashboard shows a new secret key once, through an encrypted session handoff that expires after ten minutes and is deleted on first retrieval. Deletion covers only the session that retrieved it, so two more layers stop a copy of the session taken before retrieval (a copied cookie, or concurrent requests).

- **Durable, from 0.6.0.** The first retrieval claims the key's `token_shown_at` column with `UPDATE api_keys SET token_shown_at = now WHERE id = ? AND token_shown_at IS NULL`. The database applies it atomically, so exactly one retrieval of a key's handoff ever succeeds, across processes and whatever happens to the cache. Zero rows changed (already shown, or the key no longer exists) withholds the token. The model marks the column read-only, so only that claim writes it.
- **Cache marker, from 0.5.1, kept as a second layer.** Retrieval also records the handoff's random ID in `Rails.cache` with an atomic `write(..., unless_exist: true)`. With the column it refuses a release the claim did not see (a 0.5.1 process during a rolling deploy) and covers handoffs that name no key.
- **Without the column** (not migrated yet), the gem behaves as 0.5.1: the cache marker is the only cross-copy layer. It holds only when every application process shares a cache store that implements `unless_exist:` atomically, such as Redis or Memcached, and the store retains the marker for the ten-minute handoff lifetime; a flush, a restart without persistence, or an eviction within that window lets a copy of the session taken before retrieval recover the token again until the handoff expires. `MemoryStore` covers one process; `FileStore` stops later replays on one host but not simultaneous requests; Solid Cache on PostgreSQL can let two simultaneous first retrievals both succeed; with `ActiveSupport::Cache::NullStore`, or no `Rails.cache`, the session deletion is the only protection. Run `rails generate api_keys:add_key_activity` to make the handoff durable.
- If the database or the cache raises or refuses the write, the token is withheld rather than risk a second release.
- It does not protect a stolen session: whoever holds the owner's session cookie can use the dashboard as that owner.
