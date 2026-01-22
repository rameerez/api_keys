# 🔑 `api_keys` – Secure API keys for your Rails app

[![Gem Version](https://badge.fury.io/rb/api_keys.svg)](https://badge.fury.io/rb/api_keys) [![Build Status](https://github.com/rameerez/api_keys/workflows/Tests/badge.svg)](https://github.com/rameerez/api_keys/actions)

> [!TIP]
> **🚀 Ship your next Rails app 10x faster!** I've built **[RailsFast](https://railsfast.com/?ref=api_keys)**, a production-ready Rails boilerplate template that comes with everything you need to launch a software business in days, not weeks. Go [check it out](https://railsfast.com/?ref=api_keys)!

`api_keys` makes it simple to add secure, production-ready API key authentication to any Rails app. Generate keys, restrict scopes, auto-expire tokens, revoke tokens, gate endpoints. It also provides a self-serve dashboard for your users to self-issue and manage their API keys themselves. All tokens are hashed securely by default, and never stored in plaintext.

[ 🟢 [Live interactive demo website](https://apikeys.rameerez.com) ]

![API Keys Dashboard](api_keys_dashboard.webp)

Check out my other 💎 Ruby gems: [`allgood`](https://github.com/rameerez/allgood) · [`usage_credits`](https://github.com/rameerez/usage_credits) · [`profitable`](https://github.com/rameerez/profitable) · [`nondisposable`](https://github.com/rameerez/nondisposable)

## Installation

Add this line to your application's Gemfile:

```ruby
gem "api_keys"
```

And then `bundle install`. After the gem is installed, run the generator and migration:

```bash
rails g api_keys:install
rails db:migrate
```

And you're done!

## Quick Start

Just add `has_api_keys` to your desired model. For example, if you want your `User` records to have API keys, you'd have:

```ruby
class User < ApplicationRecord
  has_api_keys
end
```

You can also customize how many maximum keys your users can have by passing a block to `has_api_keys`, like this:

```ruby
class User < ApplicationRecord
  has_api_keys do
    max_keys 10 # only 10 active API keys per user allowed
    require_name true # always require users to set a name for each API key
  end
end
```

It'd work the same if you want your `Organization` or your `Project` records to have API keys.

### Mount the dashboard engine so your users can self-serve API keys

The goal of `api_keys` is to allow you to turn your Rails app into an API platform with secure key authentication in minutes, as in: drop in this gem and you're pretty much done with API key management.

To achieve that, the gem provides a ready-to-go dashboard you can just mount in your `routes.rb` like this:

```ruby
mount ApiKeys::Engine => '/settings/api-keys'
```

#### Default behavior (User-owned keys)

By default, the dashboard expects:
- A `current_user` method that returns the currently logged-in user
- An `authenticate_user!` method that ensures a user is logged in

This works out-of-the-box with Devise and most authentication solutions where `User` owns the API keys.

#### Custom owner models (Organization, Team, etc.)

If your API keys belong to a different model (e.g., `Organization`), you **must** configure the dashboard in your initializer:

```ruby
# config/initializers/api_keys.rb
ApiKeys.configure do |config|
  # Tell the dashboard how to find the current API key owner
  config.current_owner_method = :current_organization
  
  # Tell the dashboard how to ensure the owner is authenticated
  config.authenticate_owner_method = :authenticate_organization!
end
```

These methods must exist in your `ApplicationController` (or wherever the engine is mounted). For example:

```ruby
class ApplicationController < ActionController::Base
  def current_organization
    # Your logic to return the current organization
    @current_organization ||= Organization.find(session[:organization_id])
  end
  
  def authenticate_organization!
    redirect_to login_path unless current_organization
  end
end
```

#### Common scenarios

**Organization with user membership:**
```ruby
# When organizations own keys but users manage them
config.current_owner_method = :current_organization
config.authenticate_owner_method = :require_organization_member!
```

**Multi-tenant applications:**
```ruby
# When each tenant/account owns keys
config.current_owner_method = :current_account
config.authenticate_owner_method = :authenticate_account!
```

**Team-based ownership:**
```ruby
# When teams own keys
config.current_owner_method = :current_team  
config.authenticate_owner_method = :ensure_team_access!
```

#### What the dashboard provides

Once configured, your users can:
- self-issue new API keys
- set expiration dates
- attach scopes / permissions to individual keys
- add and edit the key names
- revoke instantly
- see the status of all their keys

It provides an UI with everything you'd expect from an API keys dashboard, working right out of the box:

![API Keys Dashboard](api_keys_token.webp)

To make the experience between your app and the `api_keys` dashboard more seamless, you can configure a `return_url` and `return_text` so your users can quickly go back to your app or settings page (in the screenshot above, that's the "Home" links, text customizable)

You can check out the dashboard on the [live demo website](https://apikeys.rameerez.com).


## How it works

### Issuing new API keys

If you want to write your own front-end instead of using the provided dashboard, or just want to issue API keys at any point, you can do it with `create_api_key!`:

```ruby
@api_key = @user.create_api_key!(
  name: "my-key",
  scopes: "['read', 'write']",
  expires_at: 42.days.from_now
)

# Get the plaintext token only available upon creation
plaintext_token = @api_key.token
# => ak_123abc...
```

For security reasons, the **gem does not store the generated key** in the database.

We only store a secure hash (SHA256 by default), so the API key / API token itself is only available in plaintext immediately after creation, as `@api_key.token` – the `.token` method won't work any other time.

With this token, your users can make calls to your endpoints by attaching it as an `"Authorization: Bearer ak_123abc..."` in their HTTP calls headers, like this:

```bash
curl -X GET -H "Authorization: Bearer ak_123abc..."   "http://example.com/api/endpoint"
```

### Listing all keys for users

Of course, you can list all API keys for any record like this:
```ruby
  @user.api_keys
```

You can filter by active keys, expired keys, revoked keys:
```ruby
  @user.api_keys.active
  @user.api_keys.expired
  @user.api_keys.revoked
  @user.api_keys.inactive # expired or revoked
```

### Useful API key methods

Check if an API key is still active and therefore allowed to perform actions:
```ruby
@api_key.active?
# => true
```

Or expired:
```ruby
@api_key.expired?
# => false
```

You can revoke (disable, make inactive) any API key at any point like this:
```ruby
@api_key.revoke!
```

And you can check if an API key is revoked like this:
```ruby
@api_key.revoked?
# => true
```

And for any API key, you can always display a safe, user-friendly masked token to display on user interfaces so users can easily identify their keys:
```ruby
@api_key.masked_token
# => "ak_demo_••••yZn9"
```

### Scopes: define and verify API Key permissions

Users can limit what each API key does by selecting scopes, and you can define those scopes.

In the `config/initializers/api_keys.rb` initializer generated when you installed the gem, you'll find an option to define global scopes:
```ruby
config.default_scopes = ["read", "write"]
```

These will be the available permissions you'll see, for example, in the API Keys dashboard:

![API Keys Dashboard](api_keys_permissions.webp)

You can also define per-model scopes by passing the option to the `has_api_keys` block, which overrides global defaults:

```ruby
class User < ApplicationRecord
  has_api_keys do
    max_keys 10
    default_scopes %w[read write admin]
  end
end
```

You can get as granular with your scopes as you'd like, think for example AWS-like strings of the form: `"s3:GetObject"` – how you set this up is up to you! Scopes take any string: we recommend sticking to simple verbs (`"read"`, `"write"`) or `"resource:action"` (case-sensitive!)

You can check if an API key is allowed to do actions by checking its scopes:
```ruby
@api_key.allows_scope?("read")
# => true
```

## Controllers: secure your API endpoints

To add the `api_keys` functionality to your controllers, just use the `ApiKeys::Controller` concern and you'll have all controller methods available:
```ruby
class ApiController < ApplicationController
  include ApiKeys::Controller # provides authenticate_api_key! and current_api_key_owner
end
```

With this, you get the `authenticate_api_key!` and `current_api_key_owner` methods, which come in handy to build your key-gated actions.

### Require an API key for an endpoint

If you just want to check the presence of a valid (active, non-expired, non-revoked) API key for an endpoint, you can do:

```ruby
before_action :authenticate_api_key!
```

And of course, if you want to have unauthenticated endpoints:

```ruby
before_action :authenticate_api_key!, except: [:unauthenticated_endpoint]
```

`authenticate_api_key!` will return `401 Unauthenticated` for anything that's not a valid API key.

It will also load the valid API key, if any, to a `current_api_key` variable, that returns an API Key object (`ApiKeys::ApiKey`) on which you can call all the methods we've outlined above, and access any attribute, like:

```ruby
current_api_key.expires_at
# => 2025-05-25 05:25:05.250525000 UTC +00:00
```

If the API key has an owner, you can also access it either with `current_api_key.owner` or with the helper method `current_api_key_owner`

For example, if the owner of the API key is a `User`, you might do something like:
```ruby
current_api_key_owner.email
# => john.doe@example.com
```

### Require a scope for an endpoint

You can require a specific scope for any endpoint like:
```ruby
authenticate_api_key!(scope: "write")
```

It may be cleaner if you pass it as a Proc to `before_action` – and it may result in better-organized code if you do it endpoint-per-endpoint, immediately before each method definition, like this:

```ruby
before_action -> { authenticate_api_key!(scope: "write") }, only: [:write_action]
def write_action
  # We'll only get here if the API key is active AND it has the right scope, so execute the actual logic of the endpoint and return success:
  render json: {
    # Your success JSON...
  }, status: :ok
end
```

### Rate limit your API endpoints

Rails 8 introduced the native, built-in `rate_limit` to easily rate limit your endpoints, so `Rack::Attack` is no longer necessary! While this is not an `api_keys` feature per se, I thought it'd be nice to include an example here because it pairs so well with `api_keys`.

For example, if you want to rate limit an endpoint to only accept 2 requests each 10 seconds, per API key, you'd do something like:
```ruby
before_action -> { authenticate_api_key! }, only: [:rate_limited_action]
rate_limit to: 2, within: 10.seconds,
            by: -> { current_api_key&.id }, # Limit per API key ID
            with: -> { render json: { error: "rate_limited", message: "Too many requests (max 2 per 10 seconds per key). Please wait." }, status: :too_many_requests },
            only: [:rate_limited_action]
def rate_limited_action
  render json: {
    # Success JSON
  }, status: :ok
end
```

This `rate_limit` feature depends on Rails 8+ and an active, well-configured cache store, like [`solid_cache`](https://github.com/rails/solid_cache), which comes by default in Rails 8.

If you're still on early versions of Rails, you can still use `api_keys`! No need to implement `rate_limit` – just an idea if you're already on Rails 8!


## Configuration and settings

The gem installation creates an initializer at `config/initializers/api_keys.rb`

The default initializer is self-explanatory and self-documented, please consider spending a bit of time reading through it if you want to fine-tune the gem.

### Token prefixes

API keys are generated with a prefix followed by random characters:

```
ak_7Hq2mJ6vK9pRs3xYz9...
^^        ^^^^^^^^^^^
prefix    random part
```

The prefix makes it easy to identify API keys at a glance (in logs, code reviews, etc.) and helps services like GitHub detect leaked credentials.

**Simple mode (default):** All keys use the same prefix from `token_prefix`:
```ruby
config.token_prefix = -> { "myapp_" }  # → myapp_abc123...
```

**Key types mode:** When you configure `key_types`, different key types get different prefixes based on their type and environment (Stripe-style):
```ruby
# With key_types configured, prefixes come from the type configuration:
# publishable + test → pk_test_abc123...
# secret + live → sk_live_xyz789...
```

#### Prefix precedence

When using key types, here's how the prefix is determined:

| `key_types` Config | `key_type` Param | Resulting Prefix |
|-------------------|------------------|------------------|
| `{}` (disabled) | any | Uses `token_prefix` → `"ak_..."` |
| Configured | `nil` | Uses `token_prefix` → `"ak_..."` |
| Configured | `:publishable` | Uses type config → `"pk_test_..."` |
| Configured | `:secret` | Uses type config → `"sk_live_..."` |

In short: `token_prefix` is only used when key types are not configured OR when creating a key without specifying a `key_type`. When you specify both `key_types` config and a `key_type` parameter, the prefix comes entirely from the key type configuration.

See the [Key Types](#key-types-stripe-style-publishable--secret-keys) section below for full details.

Some highlights:

### Accept API keys via query params instead of Authentication HTTP headers

By default, the `api_key` gem expects API keys to come *exclusively* as HTTP Authentication Bearer tokens, for security purposes. But you can allow users to make requests to your endpoints with the API key token passed as a URL query param too, like this:

```
https://example.com/api/endpoint?api_key=ak_123abc...
```

This is not recommended security-wise because you'll be leaking API tokens everywhere in your logs, but if you want to enable this, just set the query param name you're expecting the API key token to be in:

```ruby
config.query_param = "api_key"
```

### Changing the hashing function to `bcrypt` for maximum security

By default, the `api_keys` gem hashes tokens using `sha256`, which is the industry standard for API keys (used by Stripe, GitHub, AWS). SHA256 is secure for high-entropy tokens because the 192 bits of randomness make brute-force attacks computationally infeasible. We use SHA256 and not other hasing algorithms for fast token lookup and low-latency API authentication.

If you need slower, password-grade hashing (e.g., for extremely sensitive tokens), you can switch to bcrypt:

```ruby
config.hash_strategy = :bcrypt
```

Note: bcrypt is ~50–100x slower than SHA256. For most API use cases, sha256 is more than sufficient.

`sha256` has O(1) lookup, `bcrypt` doesn't. This means that if you switch to `bcrypt`, you may observe ~100ms lags on every API call, for every token auth that's not cached.

For 99% of APIs, `sha256` is more than secure enough — and far better for performance.

### Increase cache TTL

We cache token lookups to improve performance, especially for repeated requests. This keeps `bcrypt` and `sha256` strategies fast under load.

By default, we use a 5-second TTL, which offers a strong balance: most requests benefit from caching, while revoked keys stop working almost immediately.

If security is your top priority (e.g. rapid revocation after suspected key compromise), you can disable caching entirely:

```ruby
config.cache_ttl = 0.seconds # disables caching
```

If performance matters more than real-time revocation, increase the TTL to reduce DB hits:

```ruby
config.cache_ttl = 2.minutes # boosts performance at cost of slower revocation
```

⚠️ Security note: Revoked keys may remain valid for up to cache_ttl. For strict real-time revocation, set cache_ttl = 0.


## Callbacks: analytics, logging, usage monitoring & auditing

The gem offers two callbacks that get executed every single time an API key is checked and authenticated (through `authenticate_api_key!` in controllers, for example)

You can define logic for them:
```ruby
config.before_authentication = ->(request) { Rails.logger.info "Authenticating request: #{request.uuid}" }

config.after_authentication = ->(result) { MyAnalytics.track_auth(result) }
```

This is especially useful if you want to build custom monitoring, usage tracking or auditing systems on top of the `api_keys` gem.

Since these callbacks get called every single time an endpoint request is made, we can't just execute the code synchronously, blocking the thread and making the endpoint lag. Instead, we enqueue an async job that process the callback code, however long it is. You can configure which queue these jobs get enqueued to.

The downside of this, of course, is that callbacks will only work if you have a valid, well-configured Active Job backend for your Rails app, like Sidekiq or [`solid_queue`](https://github.com/rails/solid_queue/), which comes by default in Rails 8. If Active Job is not well configured, well, your callbacks just won't get executed.

There's also a `track_requests_count` config option that you can turn on so the gem keeps track of how many requests has each API key made. When this is on, you may access the count like this:
```ruby
@api_key.requests_count
# => 4567
```

But again, this is turned off by default for performance purposes, and depends on having a working, well-configured Active Job backend.

## Key Types: Stripe-style Publishable & Secret Keys

For applications that distribute software with embedded API keys (desktop apps, mobile apps, CLI tools), you may want to differentiate between key types with different permission levels. The `api_keys` gem supports Stripe-style publishable/secret key types with optional test/live environment isolation.

### Why Key Types?

When you distribute software with an embedded API key, that key can potentially be extracted by malicious users. Key types solve this by letting you create:

- **Publishable keys** (`pk_test_...`, `pk_live_...`): Safe to embed in distributed apps. Limited permissions (e.g., can only validate licenses, not issue new ones). Cannot be revoked (to prevent accidentally breaking all deployed apps).

- **Secret keys** (`sk_test_...`, `sk_live_...`): Full access, meant for server-side use only. Can be revoked anytime.

### Configuration

Enable key types in your initializer:

```ruby
# config/initializers/api_keys.rb
ApiKeys.configure do |config|
  config.key_types = {
    publishable: {
      prefix: "pk",                    # Token prefix → pk_test_, pk_live_
      permissions: %w[read validate],  # Scope ceiling (max permissions allowed)
      revocable: false,                # Cannot be revoked or deleted
      limit: 1                         # Max 1 per owner per environment
    },
    secret: {
      prefix: "sk",
      permissions: :all                # No scope restrictions
      # revocable defaults to true, limit defaults to nil (unlimited)
    }
  }

  config.environments = {
    test: { prefix_segment: "test" },  # → pk_test_, sk_test_
    live: { prefix_segment: "live" }   # → pk_live_, sk_live_
  }

  # Detect current environment automatically
  config.current_environment = -> { Rails.env.production? ? :live : :test }

  # Enable strict environment isolation (test keys fail in prod, live keys fail in dev)
  config.strict_environment_isolation = true
end
```

### Creating Typed Keys

```ruby
# Create a publishable key (limited permissions, cannot be revoked)
pk = user.create_api_key!(
  name: "Production App",
  key_type: :publishable,
  environment: :live  # Optional, defaults to current_environment
)
pk.token  # => "pk_live_abc123..."

# Create a secret key (full access)
sk = user.create_api_key!(
  name: "Admin Dashboard",
  key_type: :secret
)
sk.token  # => "sk_test_xyz789..."
```

### Scope Ceiling

When a key type has limited `permissions`, any scopes you pass are filtered:

```ruby
# Publishable keys can only have read/validate permissions
pk = user.create_api_key!(
  key_type: :publishable,
  scopes: %w[read validate issue_license admin]  # Tries to request all
)
pk.scopes  # => ["read", "validate"]  # Only allowed scopes kept

# Secret keys with permissions: :all keep everything
sk = user.create_api_key!(
  key_type: :secret,
  scopes: %w[read validate issue_license admin]
)
sk.scopes  # => ["read", "validate", "issue_license", "admin"]
```

### Non-Revocable Keys

Keys with `revocable: false` protect against accidental deletion:

```ruby
pk = user.create_api_key!(key_type: :publishable)

pk.revocable?  # => false
pk.revoke!     # Raises ApiKeys::Errors::KeyNotRevocableError
pk.destroy!    # Raises ApiKeys::Errors::KeyNotRevocableError
```

The dashboard UI automatically hides the revoke button for non-revocable keys.

### Public Keys (Viewable Tokens)

#### The Problem: Non-Revocable Key Lockout

Non-revocable keys create a potential UX nightmare: if a user creates a publishable key, doesn't copy it immediately, and closes the page—they're locked out. The token is gone forever (we only store the hash), and they can't delete the key to create a new one (it's non-revocable). They're stuck with a useless key slot they can never use or remove.

This is especially problematic when combined with `limit: 1`, which restricts users to a single publishable key per environment. A user who loses their token would be permanently locked out of creating publishable keys.

#### The Solution: Storing Public Keys

For publishable keys—which are *designed* to be embedded in client-side code and distributed apps—there's no security benefit to hiding the token. These keys are meant to be public! Stripe, for example, lets you view your publishable key anytime in the dashboard.

The `public: true` option stores the plaintext token in metadata so users can view it again:

```ruby
config.key_types = {
  publishable: {
    prefix: "pk",
    permissions: %w[read validate],
    revocable: false,
    public: true,   # Store token for later viewing
    limit: 1
  },
  secret: {
    prefix: "sk",
    permissions: :all
    # public: false (default) - NEVER store secret keys!
  }
}
```

#### Security: Why This is Safe

> [!IMPORTANT]
> The `public` option only works when BOTH conditions are met:
>  - `public: true` is set in the key type configuration
>  - `revocable: false` is set (non-revocable keys only)

This double-check is a deliberate safety measure:

1. **Secret keys are NEVER stored** — Even if you accidentally set `public: true` on a secret key type, the gem checks for `revocable: false` as well. Secret keys are revocable by default, so they're protected.

2. **Revocable keys are NEVER stored** — If a key can be revoked, users can always delete it and create a new one. There's no lockout risk, so no need to store the token.

3. **Only truly public keys are stored** — Publishable keys with limited permissions, designed for client-side embedding, are the only keys that get stored. These tokens provide no security benefit when hidden—they're meant to be distributed.

> [!WARNING]
> ⚠️ **Never set `public: true` on secret keys or any key type with sensitive permissions.** The gem prevents this by requiring `revocable: false`, but you should also never configure it that way.

When a key is public, the dashboard shows a "Show" button to reveal the full token:

```ruby
pk = user.create_api_key!(key_type: :publishable)
pk.public_key_type?  # => true
pk.viewable_token    # => "pk_test_abc123..." (the full token)

sk = user.create_api_key!(key_type: :secret)
sk.public_key_type?  # => false
sk.viewable_token    # => nil (not stored)
```

### Environment Isolation

With `strict_environment_isolation = true`, keys can only authenticate in their matching environment:

```ruby
# In production (current_environment returns :live)
# A test key will fail authentication with error_code: :environment_mismatch
```

This prevents accidentally using test keys in production (or vice versa).

### Key Limits

The `limit` option restricts how many keys of a type can exist per owner per environment:

```ruby
# With limit: 1 for publishable keys
user.create_api_key!(key_type: :publishable, environment: :test)  # Works
user.create_api_key!(key_type: :publishable, environment: :test)  # Raises validation error

# But can have one per environment
user.create_api_key!(key_type: :publishable, environment: :live)  # Works
```

### Sandbox/Live Naming

You can use any environment names. For Stripe-style sandbox:

```ruby
config.environments = {
  sandbox: { prefix_segment: "test" },  # → pk_test_
  live: { prefix_segment: "live" }      # → pk_live_
}
```

### Upgrading Existing Installations

If you're adding key types to an existing installation, run the migration generator:

```bash
rails g api_keys:add_key_types
rails db:migrate
```

Existing keys without `key_type`/`environment` continue to work normally (backwards compatible).

## Enterprise-ready by design
The `api_keys` gem ships with:

 - Flexible storage
 - Async hooks
 - ActiveJob support
 - Polymorphic ownership (User, Org, etc.)
 - Custom scopes
 - Production caching
 - Tracking of last time each key was used
 - Usage tracking
 - SHA256 fallback

Making it enterprise-ready, built with extensibility and compliance in mind.

## Roadmap
  - [ ] Automatic rotation policy helpers
  - [ ] Key-pair / HMAC option

## Demo Rails app

There's a demo Rails app showcasing the features in the `api_keys` gem under `test/dummy`. It's currently deployed to `apikeys.rameerez.com`. If you want to run it yourself locally, you can just clone this repo, `cd` into the `test/dummy` folder, and then `bundle` and `rails s` to launch it. You can examine the code of the demo app to better understand the gem.

## Testing

Run the test suite with `bundle exec rake test`

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`.

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/rameerez/api_keys. Our code of conduct is: just be nice and make your mom proud of what you do and post online.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).
