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
