# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](Https://conventionalcommits.org) for commit guidelines.

<!-- changelog -->

## [v4.5.1](https://github.com/team-alembic/ash_authentication/compare/v4.5.0...v4.5.1) (2025-02-14)




### Improvements:

* note on token error about upgrading ash_postgres

## [v4.5.0](https://github.com/team-alembic/ash_authentication/compare/v4.4.9...v4.5.0) (2025-02-13)




### Features:

* Add a `log_out_everywhere` add-on (#907)

* Add a `log_out_everywhere` add-on

### Bug Fixes:

* ensure that the token resource has only `:jti` as a primary key (#908)

* Sign in tokens only last 60 seconds, but they should still be revoked after use. (#906)

## [v4.4.9](https://github.com/team-alembic/ash_authentication/compare/v4.4.8...v4.4.9) (2025-02-11)




### Bug Fixes:

* Ensure that installer generated token revocation checking action is correct. (#905)

## [v4.4.8](https://github.com/team-alembic/ash_authentication/compare/v4.4.7...v4.4.8) (2025-02-04)




### Bug Fixes:

* fix marking hashed_password as `allow_nil?` in magic link installer

### Improvements:

* Allow authorization params to be defined using secret module (#900)

## [v4.4.7](https://github.com/team-alembic/ash_authentication/compare/v4.4.6...v4.4.7) (2025-02-02)




### Bug Fixes:

* downgrade assent

* OIDC: Not retrieving remote OIDC configuration.

## [v4.4.6](https://github.com/team-alembic/ash_authentication/compare/v4.4.5...v4.4.6) (2025-02-01)




### Bug Fixes:

* OIDC: Not retrieving remote OIDC configuration.

## [v4.4.5](https://github.com/team-alembic/ash_authentication/compare/v4.4.4...v4.4.5) (2025-01-27)




### Improvements:

* Add support for OAuth2 Code Verifier (#896)

## [v4.4.4](https://github.com/team-alembic/ash_authentication/compare/v4.4.3...v4.4.4) (2025-01-23)




### Improvements:

* make `hashed_password` optional if magic_link is also used

## [v4.4.3](https://github.com/team-alembic/ash_authentication/compare/v4.4.2...v4.4.3) (2025-01-23)




### Bug Fixes:

* downgrade assent and upgrade markdown files

## [v4.4.2](https://github.com/team-alembic/ash_authentication/compare/v4.4.1...v4.4.2) (2025-01-22)




### Bug Fixes:

* Format code and update cheat sheets (both part of currently failing build)

### Improvements:

* support sqlite in the installer

* Make the links in generated emails, clickable links (#890)

## [v4.4.1](https://github.com/team-alembic/ash_authentication/compare/v4.4.0...v4.4.1) (2025-01-16)




### Bug Fixes:

* without phoenix, don't use verified routes

## [v4.4.0](https://github.com/team-alembic/ash_authentication/compare/v4.3.12...v4.4.0) (2025-01-16)




### Features:

* add email sender igniters for swoosh (#835)

### Bug Fixes:

* properly parse multiple authentication strategies

## [v4.3.12](https://github.com/team-alembic/ash_authentication/compare/v4.3.11...v4.3.12) (2025-01-14)




### Bug Fixes:

* Fixed a link in the docs and pinned `Assent` to `0.2` (#884)

## [v4.3.11](https://github.com/team-alembic/ash_authentication/compare/v4.3.10...v4.3.11) (2025-01-13)




### Bug Fixes:

* fix google strategy dependency was requiring options it should not

* fixed `:sign_in_with_token` that was logging in user automatically even if confirmation is required and account is not confirmed (#875)

* don't pass argv through to resource generator

* convert UID to string when setting (#870)

* Fix converting tenant to string (#868)

* wrong Enum.concat in validate_attribute_unique_constraint (#869)

### Improvements:

* Removed use of `Assent.Config` (#877)

## [v4.3.10](https://github.com/team-alembic/ash_authentication/compare/v4.3.9...v4.3.10) (2025-01-02)




### Bug Fixes:

* generate change_password action with `require_atomic? false`

### Improvements:

* make unconfirmed user error like other errors

## [v4.3.9](https://github.com/team-alembic/ash_authentication/compare/v4.3.8...v4.3.9) (2024-12-31)




### Bug Fixes:

* move change_password action to password strategy setup

## [v4.3.8](https://github.com/team-alembic/ash_authentication/compare/v4.3.7...v4.3.8) (2024-12-31)




### Improvements:

* add `require_confirmed_with` option to password strategy  (#861)

## [v4.3.7](https://github.com/team-alembic/ash_authentication/compare/v4.3.6...v4.3.7) (2024-12-26)




### Bug Fixes:

* return an `AuthenticationFailed` error properly

* go back to generating the repo if its unavailable

* don't generate repo if its not present

### Improvements:

* use ets if postgres isn't available

* add `change_password` action to generated code

* use better action name for password reset

## [v4.3.6](https://github.com/team-alembic/ash_authentication/compare/v4.3.5...v4.3.6) (2024-12-20)




### Improvements:

* make igniter optional

* store all tokens by default in generators

## [v4.3.5](https://github.com/team-alembic/ash_authentication/compare/v4.3.4...v4.3.5) (2024-12-12)




### Bug Fixes:

* ensure that `auto_confirm_actions` does not override

* include tenant when checking identity conflicts

* handle tokens without a primary key encoded in sub, using `identity`

### Improvements:

* allow setting identity field to allow nil with password

## [v4.3.4](https://github.com/team-alembic/ash_authentication/compare/v4.3.3...v4.3.4) (2024-12-02)




### Bug Fixes:

* ensure tenant is passed through on password reset request

* invalidate magic link sign in on invalid token

* pass opts to confirm action invocations

### Improvements:

* add primary read action to users resource for atomic upgrade

* auto confirm on sign in with magic link in generators

* Add opts to retrieve funs of AshAuthentication.Plug.Helpers (#847)

## [v4.3.3](https://github.com/team-alembic/ash_authentication/compare/v4.3.2...v4.3.3) (2024-11-14)




### Bug Fixes:

* Use correct typespec for `AshAuthentication.Sender.send/3` callback (#836)

## [v4.3.2](https://github.com/team-alembic/ash_authentication/compare/v4.3.1...v4.3.2) (2024-11-13)




### Bug Fixes:

* The documentation says that we ignore sender returns, so we need to ignore them. (#838)

## [v4.3.1](https://github.com/team-alembic/ash_authentication/compare/v4.3.0...v4.3.1) (2024-11-12)




### Bug Fixes:

* RequestPasswordReset: fails when action called directly. (#833)

* ash_authentication.add_strategy: Generated password reset action names did not match the defaults. (#834)

* confirmation warning 'changeset has already been validated for action'

## [v4.3.0](https://github.com/team-alembic/ash_authentication/compare/v4.2.7...v4.3.0) (2024-11-05)




### Features:

* Strategy.Slack: Add direct support for Slack strategy. (#825)

* Strategy.Slack: Add direct support for Slack strategy.

### Bug Fixes:

* handle igniter/rewrite upgrades

* set sign_in_with_token action name properly

## [v4.2.7](https://github.com/team-alembic/ash_authentication/compare/v4.2.6...v4.2.7) (2024-11-01)




### Bug Fixes:

* change_attribute -> force_* to eliminate waring

## [v4.2.6](https://github.com/team-alembic/ash_authentication/compare/v4.2.5...v4.2.6) (2024-10-31)




### Improvements:

* run codegen after adding an auth strategy

## [v4.2.5](https://github.com/team-alembic/ash_authentication/compare/v4.2.4...v4.2.5) (2024-10-23)




### Bug Fixes:

* proper error instead of match error on not found user

## [v4.2.4](https://github.com/team-alembic/ash_authentication/compare/v4.2.3...v4.2.4) (2024-10-23)




### Bug Fixes:

* generate link using `confirm` instead of `token` in the generators

## [v4.2.3](https://github.com/team-alembic/ash_authentication/compare/v4.2.2...v4.2.3) (2024-10-19)




### Bug Fixes:

* respond to `--auth-strategy` option in installer

* issues with OIDC strategy (#800)

## [v4.2.2](https://github.com/team-alembic/ash_authentication/compare/v4.2.1...v4.2.2) (2024-10-15)




### Improvements:

* support registration via magic link (#796)

* support registration via magic link

* prevent account takeover hijacking by protecting against upserts against unconfirmed records

* add confirmation add on when identity_field is email

* implement our own identity checking instead of relying on eager_check

## [v4.2.1](https://github.com/team-alembic/ash_authentication/compare/v4.2.0...v4.2.1) (2024-10-14)




### Improvements:

* update igniter

## [v4.2.0](https://github.com/team-alembic/ash_authentication/compare/v4.1.0...v4.2.0) (2024-10-07)




### Features:

* add_strategy task (#794)

### Improvements:

* add `ash_authentication.add_strategy` task

* add atomic implementations for various changes/validations

* support `--auth-strategy` option when installing

## [v4.1.0](https://github.com/team-alembic/ash_authentication/compare/v4.0.4...v4.1.0) (2024-10-06)




### Features:

* Add AshAuthentication igniter installer (#782)

### Bug Fixes:

* handle options properly for subect to user (#786)

* setup options properly for ash 3.0 (#785)

### Improvements:

* igniter installer for user & user token resources

## [v4.0.4](https://github.com/team-alembic/ash_authentication/compare/v4.0.3...v4.0.4) (2024-09-01)




### Bug Fixes:

* update types and formatter

* add secret values to config

* sort new fields

* sort new types

* properly set allow_nil for apple secrets

* credo and sobelow warnings

### Improvements:

* add apple strategy (#750)

* add apple strategy

## [v4.0.3](https://github.com/team-alembic/ash_authentication/compare/v4.0.2...v4.0.3) (2024-08-22)




### Bug Fixes:

* allow overriding strategy defaults (#766)

* bug where `nil` is not allowed but is returned from secret functions.

* add back in accidentally removed debug errors code (#768)

* set options earlier in magic link/oauth2

### Improvements:

* avoid warning about comparison with `nil`

* set context in addition to tenant

* use `no_depend_modules` for better compile dependencies

* enable custom `http_adapters` (#760)

## [v4.0.2](https://github.com/team-alembic/ash_authentication/compare/v4.0.1...v4.0.2) (2024-08-05)




### Bug Fixes:

* only pass the "token" parameter to reset with token action (#748)

* handle case where `action.accept` is `nil`

### Improvements:

* validate that tokens are enabled when password resets are enabled. (#758)

* compile-time check to make sure that the configured `token_resource` is an Ash.Resource (#749)

* Tokens: improved compile-time validation of the token_resource option of the tokens DSL by checking that the passed value is an Ash.Resource.

* Tokens: removed unnecessary stuff from the test file.

* Tokens: fixed credo warning and changed some things after PR feedback

## [v4.0.1](https://github.com/team-alembic/ash_authentication/compare/v4.0.0...v4.0.1) (2024-06-11)




### Bug Fixes:

* no need to `allow_nil_input` for an unaccepted field

* correctly generate sign-in tokens when requested.

* ensure tenant is set when revoking tokens and on changeset for updating

* broken links in readme (#692)

* broken links

* bug in tokens required verifier.

## [4.0.0](https://github.com/team-alembic/ash_authentication/compare/v4.0.0-rc.7...4.0.0) (2024-05-10)
### Breaking Changes:

* Sign in tokens are enabled by default for the password strategy.

* Tokens are now enabled by default.



### Bug Fixes:

* Jwt: Include authentication interaction context when storing tokens.

* Strategy.Password: Reset tokens are single use. (#625)

* Confirmation: Only allow the confirmation token to be used once. (#623)

### Improvements:

* Only require tokens to be enabled when using a strategy which needs them.

* OIDC: Adjust dsl of OIDC reflect assent requirements (#538)

* Use `Ash` functions instead of generated domain functions.

## [v4.0.0-rc.7](https://github.com/team-alembic/ash_authentication/compare/v4.0.0-rc.6...v4.0.0-rc.7) (2024-05-10)




### Bug Fixes:

* Jwt: Include authentication interaction context when storing tokens.

### Improvements:

* Only require tokens to be enabled when using a strategy which needs them.

## [v4.0.0-rc.6](https://github.com/team-alembic/ash_authentication/compare/v4.0.0-rc.5...v4.0.0-rc.6) (2024-04-11)




### Improvements:

* OIDC: Adjust dsl of OIDC reflect assent requirements (#538)

## [v4.0.0-rc.5](https://github.com/team-alembic/ash_authentication/compare/v4.0.0-rc.4...v4.0.0-rc.5) (2024-04-10)

### Breaking Changes:

- Sign in tokens are enabled by default for the password strategy.

- Tokens are now enabled by default.

### Bug Fixes:

- Strategy.Password: Reset tokens are single use. (#625)

## [v4.0.0-rc.4](https://github.com/team-alembic/ash_authentication/compare/v4.0.0-rc.3...v4.0.0-rc.4) (2024-04-09)

### Improvements:

- Use `Ash` functions instead of generated domain functions.

## [v4.0.0-rc.3](https://github.com/team-alembic/ash_authentication/compare/v4.0.0-rc.2...v4.0.0-rc.3) (2024-04-08)

### Bug Fixes:

- Confirmation: Only allow the confirmation token to be used once. (#623)

## [v4.0.0-rc.2](https://github.com/team-alembic/ash_authentication/compare/v4.0.0-rc.1...v4.0.0-rc.2) (2024-04-02)

### Breaking Changes:

- Update to support Ash 3.0. (#599)

### Bug Fixes:

- allow future versions of ash rc

- Jwt: Ignore pre-release versions verifying token versions.

### Improvements:

- re-integrate ash_graphql and ash_json_api RCs.

## [v4.0.0-rc.1](https://github.com/team-alembic/ash_authentication/compare/v4.0.0-rc.0...v4.0.0-rc.1) (2024-04-01)

### Improvements:

- re-integrate ash_graphql and ash_json_api RCs.

## [v4.0.0-rc.0](https://github.com/team-alembic/ash_authentication/compare/v3.12.4...v4.0.0-rc.0) (2024-03-28)

### Breaking Changes:

- Update to support Ash 3.0. (#599)

### Bug Fixes:

- Jwt: Ignore pre-release versions verifying token versions.

## [v3.12.4](https://github.com/team-alembic/ash_authentication/compare/v3.12.3...v3.12.4) (2024-03-11)

### Improvements:

- infer `api` from a resource

## [v3.12.3](https://github.com/team-alembic/ash_authentication/compare/v3.12.2...v3.12.3) (2024-02-20)

## [v3.12.2](https://github.com/team-alembic/ash_authentication/compare/v3.12.1...v3.12.2) (2024-01-30)

### Bug Fixes:

- deps: mark ash_postgres as optional

### Improvements:

- support atom keys for uid in addition to strings (#556)

## [v3.12.1](https://github.com/team-alembic/ash_authentication/compare/v3.12.0...v3.12.1) (2024-01-25)

### Improvements:

- support atom keys for uid in addition to strings (#556)

## [v3.12.0](https://github.com/team-alembic/ash_authentication/compare/v3.11.16...v3.12.0) (2023-11-21)

### Features:

- Add Google strategy (#474)

- Add Google strategy

### Bug Fixes:

- include Google strategy cheat sheet

- Add documentation grouping for Google strategy

### Improvements:

- Change redirect_uri secret to be more flexible (#473)

## [v3.11.16](https://github.com/team-alembic/ash_authentication/compare/v3.11.15...v3.11.16) (2023-10-25)

### Bug Fixes:

- Change overwriting of refresh_token to not overwrite them with nil (#483)

### Improvements:

- Add id as an option for sourcing uid for UserIdentity (#481)

## [v3.11.15](https://github.com/team-alembic/ash_authentication/compare/v3.11.14...v3.11.15) (2023-09-22)

### Bug Fixes:

- ensure we aren't calling `Map.take` on `nil`

## [v3.11.14](https://github.com/team-alembic/ash_authentication/compare/v3.11.13...v3.11.14) (2023-09-22)

### Bug Fixes:

- TokenResource: don't silently drop notifications about token removal. (#432)

## [v3.11.13](https://github.com/team-alembic/ash_authentication/compare/v3.11.12...v3.11.13) (2023-09-22)

### Improvements:

- Allow all token lifetimes to be specified with a time unit.

## [v3.11.12](https://github.com/team-alembic/ash_authentication/compare/v3.11.11...v3.11.12) (2023-09-21)

### Bug Fixes:

- include `finch` in the dependencies.

- deprecated mint httpadapter (#425)

## [v3.11.11](https://github.com/team-alembic/ash_authentication/compare/v3.11.10...v3.11.11) (2023-09-21)

### Bug Fixes:

- include `finch` in the dependencies.

- deprecated mint httpadapter (#425)

## [v3.11.10](https://github.com/team-alembic/ash_authentication/compare/v3.11.9...v3.11.10) (2023-09-18)

### Bug Fixes:

- only use sign in token expiration for sign in tokens (#424)

## [v3.11.9](https://github.com/team-alembic/ash_authentication/compare/v3.11.8...v3.11.9) (2023-09-17)

### Bug Fixes:

- support generating tokens for other strategies.

### Improvements:

- support generating sign in tokens on register (#421)

- support generating sign in tokens on register

## [v3.11.8](https://github.com/team-alembic/ash_authentication/compare/v3.11.7...v3.11.8) (2023-08-16)

### Bug Fixes:

- correct spec for `Jwt.token_for_user` (#389)

## [v3.11.7](https://github.com/team-alembic/ash_authentication/compare/v3.11.6...v3.11.7) (2023-07-14)

### Bug Fixes:

- ensure that the `current_` atom exists at compile time. (#359)

## [v3.11.6](https://github.com/team-alembic/ash_authentication/compare/v3.11.5...v3.11.6) (2023-06-23)

### Bug Fixes:

- fix Logger deprecations for elixir 1.15 (#343)

## [v3.11.5](https://github.com/team-alembic/ash_authentication/compare/v3.11.4...v3.11.5) (2023-06-18)

### Bug Fixes:

- ConfirmationHookChange: use `Info.find_strategy/2..3` rather than a hard coded strategy name. (#336)

## [v3.11.4](https://github.com/team-alembic/ash_authentication/compare/v3.11.3...v3.11.4) (2023-06-15)

### Bug Fixes:

- primary keys are implicitly uniquely constrained. (#333)

## [v3.11.3](https://github.com/team-alembic/ash_authentication/compare/v3.11.2...v3.11.3) (2023-05-31)

### Bug Fixes:

- duplicate mime type for "json".

## [v3.11.2](https://github.com/team-alembic/ash_authentication/compare/v3.11.1...v3.11.2) (2023-05-28)

### Bug Fixes:

- Strategy.Password: Preparations should allow strategy to be passed in. (#314)

## [v3.11.1](https://github.com/team-alembic/ash_authentication/compare/v3.11.0...v3.11.1) (2023-05-04)

### Bug Fixes:

- correct oauth2 and getting started typos (#267)

## [v3.11.0](https://github.com/team-alembic/ash_authentication/compare/v3.10.8...v3.11.0) (2023-05-04)

### Features:

- OpenID Connect Strategy (#197)

- AshAuthentication.Strategy.Oidc: Add OpenID Connect strategy.

## [v3.10.8](https://github.com/team-alembic/ash_authentication/compare/v3.10.7...v3.10.8) (2023-04-28)

### Bug Fixes:

- PasswordValidation should associate errors with the field being â¦ (#279)

## [v3.10.7](https://github.com/team-alembic/ash_authentication/compare/v3.10.6...v3.10.7) (2023-04-28)

### Improvements:

- run CI on pull requests

## [v3.10.6](https://github.com/team-alembic/ash_authentication/compare/v3.10.5...v3.10.6) (2023-04-09)

### Improvements:

- require spark ~> 1.0 (#261)

## [v3.10.5](https://github.com/team-alembic/ash_authentication/compare/v3.10.4...v3.10.5) (2023-04-06)

### Improvements:

- add sign in tokens to password strategy (#252)

- add sign in tokens to password strategy

- convert `sign_in_with_token` into an action.

## [v3.10.4](https://github.com/team-alembic/ash_authentication/compare/v3.10.3...v3.10.4) (2023-04-03)

### Improvements:

- update spark (#254)

- update spark

## [v3.10.3](https://github.com/team-alembic/ash_authentication/compare/v3.10.2...v3.10.3) (2023-04-03)

### Improvements:

- update spark (#254)

- update spark

## [v3.10.2](https://github.com/team-alembic/ash_authentication/compare/v3.10.1...v3.10.2) (2023-03-06)

### Bug Fixes:

- respect `identity_relationship_user_id_attribute` on `Strategy.OAuth2.IdentityChange` (#213)

## [v3.10.1](https://github.com/team-alembic/ash_authentication/compare/v3.10.0...v3.10.1) (2023-03-06)

### Bug Fixes:

- fix failing JWT tests because of bad version regex.

## [v3.10.0](https://github.com/team-alembic/ash_authentication/compare/v3.9.6...v3.10.0) (2023-03-04)

### Breaking Changes:

- Configure accepted fields on register (#219)

## [v3.9.6](https://github.com/team-alembic/ash_authentication/compare/v3.9.5...v3.9.6) (2023-03-01)

### Improvements:

- allow registration and sign in to be disabled on password strategies. (#218)

## [v3.9.5](https://github.com/team-alembic/ash_authentication/compare/v3.9.4...v3.9.5) (2023-02-23)

### Improvements:

- support multiple otp apps w/resources (#209)

## [v3.9.4](https://github.com/team-alembic/ash_authentication/compare/v3.9.3...v3.9.4) (2023-02-22)

### Improvements:

- PasswordConfirmationValidation: allow `strategy_name` to be passed as an option. (#208)

## [v3.9.3](https://github.com/team-alembic/ash_authentication/compare/v3.9.2...v3.9.3) (2023-02-19)

### Bug Fixes:

- sign in preparation without identity resource (#198)

## [v3.9.2](https://github.com/team-alembic/ash_authentication/compare/v3.9.1...v3.9.2) (2023-02-12)

### Bug Fixes:

- Password.Transformer: don't force users to define a `hashed_password` argument to the register action. (#192)

## [v3.9.1](https://github.com/team-alembic/ash_authentication/compare/v3.9.0...v3.9.1) (2023-02-12)

### Bug Fixes:

- select `hashed_password` on sign in preparation

- don't allow special purpose tokens to be used for sign in. (#191)

### Improvements:

- add select_for_senders (#189)

- add select_for_senders

- include metadata declaration on register action

## [v3.9.0](https://github.com/team-alembic/ash_authentication/compare/v3.8.0...v3.9.0) (2023-02-09)

### Features:

- Add new "magic link" authentication strategy. (#184)

### Bug Fixes:

- validate uniqueness of strategy names. (#185)

- resources can appear in multiple apis, so we need to uniq them here (#169)

- put_add_on/2 was putting into strategies

### Improvements:

- Strategy.Custom: handle custom strategies as extensions. (#183)

- improve error message for badly formed token secrets (#181)

- add metadata declarations to actions that have a `token` (#164)

- validate signing secret is a string (#163)

## [v3.8.0](https://github.com/team-alembic/ash_authentication/compare/v3.7.9...v3.8.0) (2023-02-09)

### Features:

- Add new "magic link" authentication strategy. (#184)

### Bug Fixes:

- validate uniqueness of strategy names. (#185)

- resources can appear in multiple apis, so we need to uniq them here (#169)

- put_add_on/2 was putting into strategies

### Improvements:

- Strategy.Custom: handle custom strategies as extensions. (#183)

- improve error message for badly formed token secrets (#181)

- add metadata declarations to actions that have a `token` (#164)

- validate signing secret is a string (#163)

## [v3.7.9](https://github.com/team-alembic/ash_authentication/compare/v3.7.8...v3.7.9) (2023-02-09)

### Bug Fixes:

- validate uniqueness of strategy names. (#185)

- resources can appear in multiple apis, so we need to uniq them here (#169)

- put_add_on/2 was putting into strategies

### Improvements:

- Strategy.Custom: handle custom strategies as extensions. (#183)

- improve error message for badly formed token secrets (#181)

- add metadata declarations to actions that have a `token` (#164)

- validate signing secret is a string (#163)

## [v3.7.8](https://github.com/team-alembic/ash_authentication/compare/v3.7.7...v3.7.8) (2023-02-08)

### Bug Fixes:

- resources can appear in multiple apis, so we need to uniq them here (#169)

- put_add_on/2 was putting into strategies

### Improvements:

- Strategy.Custom: handle custom strategies as extensions. (#183)

- improve error message for badly formed token secrets (#181)

- add metadata declarations to actions that have a `token` (#164)

- validate signing secret is a string (#163)

## [v3.7.7](https://github.com/team-alembic/ash_authentication/compare/v3.7.6...v3.7.7) (2023-02-06)

### Bug Fixes:

- resources can appear in multiple apis, so we need to uniq them here (#169)

- put_add_on/2 was putting into strategies

### Improvements:

- improve error message for badly formed token secrets (#181)

- add metadata declarations to actions that have a `token` (#164)

- validate signing secret is a string (#163)

## [v3.7.6](https://github.com/team-alembic/ash_authentication/compare/v3.7.5...v3.7.6) (2023-01-30)

### Bug Fixes:

- resources can appear in multiple apis, so we need to uniq them here (#169)

- put_add_on/2 was putting into strategies

### Improvements:

- add metadata declarations to actions that have a `token` (#164)

- validate signing secret is a string (#163)

## [v3.7.5](https://github.com/team-alembic/ash_authentication/compare/v3.7.4...v3.7.5) (2023-01-30)

### Improvements:

- add metadata declarations to actions that have a `token` (#164)

- validate signing secret is a string (#163)

## [v3.7.4](https://github.com/team-alembic/ash_authentication/compare/v3.7.3...v3.7.4) (2023-01-30)

### Improvements:

- validate signing secret is a string (#163)

## [v3.7.3](https://github.com/team-alembic/ash_authentication/compare/v3.7.2...v3.7.3) (2023-01-18)

### Bug Fixes:

- Password: validate fields using both methods of allowing nil input. (#151)

## [v3.7.2](https://github.com/team-alembic/ash_authentication/compare/v3.7.1...v3.7.2) (2023-01-18)

### Improvements:

- AuthenticationFailed: store a `caused_by` value in authentication failures. (#145)

## [v3.7.1](https://github.com/team-alembic/ash_authentication/compare/v3.7.0...v3.7.1) (2023-01-18)

### Improvements:

- update ash & switch to new docs patterns (#146)

## [v3.7.0](https://github.com/team-alembic/ash_authentication/compare/v3.6.1...v3.7.0) (2023-01-18)

### Features:

- PasswordValidation: Add a validation which can check a password. (#144)

## [v3.6.1](https://github.com/team-alembic/ash_authentication/compare/v3.6.0...v3.6.1) (2023-01-15)

### Bug Fixes:

- don't call `hash_provider.valid?` on `nil` values (#135)

- use configured hashed_password_field

### Improvements:

- set confirmed field to `nil`, for reconfirmation (#136)

- set confirmed field to `nil`, for reconfirmation

- only change `confirmed_at_field` if its not changing, and only on updates

## [v3.6.0](https://github.com/team-alembic/ash_authentication/compare/v3.5.3...v3.6.0) (2023-01-13)

### Breaking Changes:

- TokenResource: Store the token subject in the token resource. (#133)

- TokenResource: Store the token subject in the token resource.

### Bug Fixes:

- don't call `hash_provider.valid?` on `nil` values (#135)

- use configured hashed_password_field

## [v3.5.3](https://github.com/team-alembic/ash_authentication/compare/v3.5.2...v3.5.3) (2023-01-13)

### Bug Fixes:

- Confirmation: send the original changeset to confirmation senders. (#132)

## [v3.5.2](https://github.com/team-alembic/ash_authentication/compare/v3.5.1...v3.5.2) (2023-01-12)

### Improvements:

- add user context when creating tokens (#129)

## [v3.5.1](https://github.com/team-alembic/ash_authentication/compare/v3.5.0...v3.5.1) (2023-01-12)

### Bug Fixes:

- missing icons in OAuth2 strategies. (#126)

## [v3.5.0](https://github.com/team-alembic/ash_authentication/compare/v3.4.2...v3.5.0) (2023-01-12)

### Breaking Changes:

- GitHub: Add GitHub authentication strategy. (#125)

## [v3.4.2](https://github.com/team-alembic/ash_authentication/compare/v3.4.1...v3.4.2) (2023-01-12)

### Bug Fixes:

- improve some error message/validation logic

### Improvements:

- add policy utilities and accompanying guide (#119)

- add policy utilities and accompanying guide

- fix build/warnings/dialyzer/format

## [v3.4.1](https://github.com/team-alembic/ash_authentication/compare/v3.4.0...v3.4.1) (2023-01-12)

### Bug Fixes:

- Confirmation: correctly generate confirmation token subjects. (#124)

## [v3.4.0](https://github.com/team-alembic/ash_authentication/compare/v3.3.1...v3.4.0) (2023-01-11)

### Features:

- Add token-required-for-authentication feature. (#116)

## [v3.3.1](https://github.com/team-alembic/ash_authentication/compare/v3.3.0...v3.3.1) (2023-01-09)

### Improvements:

- Set Ash actor and tenant when executing internal plugs. (#115)

## [v3.3.0](https://github.com/team-alembic/ash_authentication/compare/v3.2.2...v3.3.0) (2023-01-09)

### Features:

- Make strategy names optional where possible. (#113)

## [v3.2.2](https://github.com/team-alembic/ash_authentication/compare/v3.2.1...v3.2.2) (2023-01-08)

### Improvements:

- Allow the strategy name to be passed for password validations and changes. (#102)

## [v3.2.1](https://github.com/team-alembic/ash_authentication/compare/v3.2.0...v3.2.1) (2022-12-16)

### Improvements:

- add `icon` field to OAuth2 strategy. (#100)

## [v3.2.0](https://github.com/team-alembic/ash_authentication/compare/v3.1.0...v3.2.0) (2022-12-16)

### Features:

- Auth0: Add a pre-configured Auth0 strategy. (#99)

## [v3.1.0](https://github.com/team-alembic/ash_authentication/compare/v3.0.4...v3.1.0) (2022-12-14)

### Breaking Changes:

- Jwt: Use token signing secret into the DSL.

### Features:

- Add option to store all tokens when they're created. (#91)

### Improvements:

- remove the need for a strategy in changeset/query contexts. (#89)

- add transaction reason

- try a simpler way of ensuring module is compiled

## [v3.0.4](https://github.com/team-alembic/ash_authentication/compare/v3.0.3...v3.0.4) (2022-12-08)

### Improvements:

- update to latest ash version

## [v3.0.3](https://github.com/team-alembic/ash_authentication/compare/v3.0.2...v3.0.3) (2022-12-07)

### Bug Fixes:

- break potential compiler dependency loops. (#64)

## [v3.0.2](https://github.com/team-alembic/ash_authentication/compare/v3.0.1...v3.0.2) (2022-12-05)

### Improvements:

- supervisor: require that the user adds the supervisor to their OTP app. (#62)

## [v3.0.1](https://github.com/team-alembic/ash_authentication/compare/v3.0.0...v3.0.1) (2022-12-05)

### Improvements:

- actions: All actions now take optional arguments for the underlying API call. (#61)

## [v3.0.0](https://github.com/team-alembic/ash_authentication/compare/v2.0.1...v3.0.0) (2022-12-04)

### Breaking Changes:

- TokenResource: Move `TokenRevocation` -> `TokenResource`.

### Improvements:

- Confirmation: Store confirmation changes in the token resource.

## [v2.0.1](https://github.com/team-alembic/ash_authentication/compare/v2.0.0...v2.0.1) (2022-11-24)

### Improvements:

- Confirmation: Confirmation is not a strategy. (#46)

- Confirmation: Confirmation is not a strategy.

- Confirmation: Support more than one confirmation entity.

## [v2.0.0](https://github.com/team-alembic/ash_authentication/compare/v1.0.0...v2.0.0) (2022-11-22)

### Breaking Changes:

- Major redesign of DSL and code structure. (#35)

## [v1.0.0](https://github.com/team-alembic/ash_authentication/compare/v0.6.1...v1.0.0) (2022-11-15)

### Breaking Changes:

- OAuth2Authentication: Make the `site` option runtime configurable. (#31)

## [v0.6.1](https://github.com/team-alembic/ash_authentication/compare/v0.6.0...v0.6.1) (2022-11-15)

### Bug Fixes:

- OAuth2Authentication: Return the failure reason even if it's not a changeset. (#29)

## [v0.6.0](https://github.com/team-alembic/ash_authentication/compare/v0.5.0...v0.6.0) (2022-11-10)

### Features:

- OAuth2Authentication: Add support for generic OAuth2 endpoints. (#28)

## [v0.5.0](https://github.com/team-alembic/ash_authentication/compare/v0.4.3...v0.5.0) (2022-11-04)

### Features:

- Confirmation: Add extension that allows a user to be confirmed when created or updated. (#27)

## [v0.4.3](https://github.com/team-alembic/ash_authentication/compare/v0.4.2...v0.4.3) (2022-11-03)

### Improvements:

- docs: Improve endpoint docs for PasswordAuthentication and PasswordReset.

## [v0.4.2](https://github.com/team-alembic/ash_authentication/compare/v0.4.1...v0.4.2) (2022-11-03)

### Bug Fixes:

- PasswordReset: Generate the reset token using the target action, not the source action. (#25)

- PasswordReset: Generate the reset token using the target action, not the source action.

### Improvements:

- PasswordReset: rework PasswordReset to be a provider in it's own right - this means it has it's own routes, etc.

## [v0.4.1](https://github.com/team-alembic/ash_authentication/compare/v0.4.0...v0.4.1) (2022-11-03)

### Improvements:

- PasswordReset: A reset request is actually a query, not an update. (#23)

## [v0.4.0](https://github.com/team-alembic/ash_authentication/compare/v0.3.0...v0.4.0) (2022-11-02)

### Features:

- PasswordReset: allow users to request and reset their password. (#22)

## [v0.3.0](https://github.com/team-alembic/ash_authentication/compare/v0.2.1...v0.3.0) (2022-10-31)

### Features:

- Ash.PlugHelpers: Support standard actor configuration. (#16)

- Ash.PlugHelpers: Support standard actor configuration.

### Improvements:

- docs: change all references to `actor` to `user`.

## [v0.2.1](https://github.com/team-alembic/ash_authentication/compare/v0.2.0...v0.2.1) (2022-10-26)

### Bug Fixes:

- deprecation warnings caused by use of `Macro.expand_literal/2`.

### Improvements:

- move subject_name uniqueness validation to compile time.

- remove `generated: true` from macros.

## [v0.2.0](https://github.com/team-alembic/ash_authentication/compare/v0.1.0...v0.2.0) (2022-10-24)

### Features:

- PasswordAuthentication: Registration and authentication with local credentials (#4)

## [v0.1.0](https://github.com/team-alembic/ash_authentication/compare/v0.1.0...v0.1.0) (2022-09-27)
