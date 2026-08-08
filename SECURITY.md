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

- trusted TLS/proxy configuration, endpoint authorization, and request rate limiting;
- encrypted, `Secure`, `HttpOnly`, appropriately `SameSite` session cookies for the one-time dashboard token handoff;
- database, cache, queue, log, backup, and observability access controls;
- filtering any query-parameter credential name from application and proxy logs if that opt-in transport is enabled;
- classifying every permission on a `public: true` key type as safe for an untrusted public client and maintaining a disable/replacement procedure for non-revocable identifiers; and
- prompt dependency/runtime patching and a durable background-job backend where callbacks or usage statistics are required.

The gem bounds authentication work, but applications should still rate-limit credential endpoints. Do not treat a key prefix, last four characters, cache entry, or public key as proof of authorization.
