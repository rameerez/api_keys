# Apikeys

[![Gem Version](https://badge.fury.io/rb/pay.svg)](https://badge.fury.io/rb/pay)

> **Turn any Rails app into an API platform in 5 minutes, with Stripe-grade security & DX.**

`apikeys` is a Ruby gem that handles secure API key generation, authentication, revocation, expiration, scopes, and provides optional self-serve UI for your Rails application users.

See the [Product Requirements Document](.cursor/prd.md) for the full vision and features.

## Installation

Add this line to your application's Gemfile:

```ruby
gem "apikeys"
```

And then execute:

```bash
$ bundle install
```

Or install it yourself as:

```bash
$ gem install apikeys
```

Then run the installer:

```bash
$ rails g apikeys:install
$ rails db:migrate
```

## Usage

_(Coming soon... See the [PRD](.cursor/prd.md) for the intended design)_.

## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake test` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and the created tag, and push the `.gem` file to [RubyGems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/your-repo/apikeys. <!-- TODO: Update link -->

## License

The gem is available as open source under the terms of the [MIT License](LICENSE.txt).

