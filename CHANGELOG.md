# Change Log

All notable changes to this project will be documented in this file.
See [Conventional Commits](Https://conventionalcommits.org) for commit guidelines.

<!-- changelog -->

## [v3.4.1](https://github.com/team-alembic/ash_authentication/compare/v3.4.0...v3.4.1) (2023-01-12)




### Bug Fixes:

* Confirmation: correctly generate confirmation token subjects. (#124)

## [v3.4.0](https://github.com/team-alembic/ash_authentication/compare/v3.3.1...v3.4.0) (2023-01-11)




### Features:

* Add token-required-for-authentication feature. (#116)

## [v3.3.1](https://github.com/team-alembic/ash_authentication/compare/v3.3.0...v3.3.1) (2023-01-09)




### Improvements:

* Set Ash actor and tenant when executing internal plugs. (#115)

## [v3.3.0](https://github.com/team-alembic/ash_authentication/compare/v3.2.2...v3.3.0) (2023-01-09)




### Features:

* Make strategy names optional where possible. (#113)

## [v3.2.2](https://github.com/team-alembic/ash_authentication/compare/v3.2.1...v3.2.2) (2023-01-08)




### Improvements:

* Allow the strategy name to be passed for password validations and changes. (#102)

## [v3.2.1](https://github.com/team-alembic/ash_authentication/compare/v3.2.0...v3.2.1) (2022-12-16)




### Improvements:

* add `icon` field to OAuth2 strategy. (#100)

## [v3.2.0](https://github.com/team-alembic/ash_authentication/compare/v3.1.0...v3.2.0) (2022-12-16)




### Features:

* Auth0: Add a pre-configured Auth0 strategy. (#99)

## [v3.1.0](https://github.com/team-alembic/ash_authentication/compare/v3.0.4...v3.1.0) (2022-12-14)
### Breaking Changes:

* Jwt: Use token signing secret into the DSL.



### Features:

* Add option to store all tokens when they're created. (#91)

### Improvements:

* remove the need for a strategy in changeset/query contexts. (#89)

* add transaction reason

* try a simpler way of ensuring module is compiled

## [v3.0.4](https://github.com/team-alembic/ash_authentication/compare/v3.0.3...v3.0.4) (2022-12-08)




### Improvements:

* update to latest ash version

## [v3.0.3](https://github.com/team-alembic/ash_authentication/compare/v3.0.2...v3.0.3) (2022-12-07)




### Bug Fixes:

* break potential compiler dependency loops. (#64)

## [v3.0.2](https://github.com/team-alembic/ash_authentication/compare/v3.0.1...v3.0.2) (2022-12-05)




### Improvements:

* supervisor: require that the user adds the supervisor to their OTP app. (#62)

## [v3.0.1](https://github.com/team-alembic/ash_authentication/compare/v3.0.0...v3.0.1) (2022-12-05)




### Improvements:

* actions: All actions now take optional arguments for the underlying API call. (#61)

## [v3.0.0](https://github.com/team-alembic/ash_authentication/compare/v2.0.1...v3.0.0) (2022-12-04)
### Breaking Changes:

* TokenResource: Move `TokenRevocation` -> `TokenResource`.



### Improvements:

* Confirmation: Store confirmation changes in the token resource.

## [v2.0.1](https://github.com/team-alembic/ash_authentication/compare/v2.0.0...v2.0.1) (2022-11-24)




### Improvements:

* Confirmation: Confirmation is not a strategy. (#46)

* Confirmation: Confirmation is not a strategy.

* Confirmation: Support more than one confirmation entity.

## [v2.0.0](https://github.com/team-alembic/ash_authentication/compare/v1.0.0...v2.0.0) (2022-11-22)
### Breaking Changes:

* Major redesign of DSL and code structure. (#35)



## [v1.0.0](https://github.com/team-alembic/ash_authentication/compare/v0.6.1...v1.0.0) (2022-11-15)
### Breaking Changes:

* OAuth2Authentication: Make the `site` option runtime configurable. (#31)



## [v0.6.1](https://github.com/team-alembic/ash_authentication/compare/v0.6.0...v0.6.1) (2022-11-15)




### Bug Fixes:

* OAuth2Authentication: Return the failure reason even if it's not a changeset. (#29)

## [v0.6.0](https://github.com/team-alembic/ash_authentication/compare/v0.5.0...v0.6.0) (2022-11-10)




### Features:

* OAuth2Authentication: Add support for generic OAuth2 endpoints. (#28)

## [v0.5.0](https://github.com/team-alembic/ash_authentication/compare/v0.4.3...v0.5.0) (2022-11-04)




### Features:

* Confirmation: Add extension that allows a user to be confirmed when created or updated. (#27)

## [v0.4.3](https://github.com/team-alembic/ash_authentication/compare/v0.4.2...v0.4.3) (2022-11-03)




### Improvements:

* docs: Improve endpoint docs for PasswordAuthentication and PasswordReset.

## [v0.4.2](https://github.com/team-alembic/ash_authentication/compare/v0.4.1...v0.4.2) (2022-11-03)




### Bug Fixes:

* PasswordReset: Generate the reset token using the target action, not the source action. (#25)

* PasswordReset: Generate the reset token using the target action, not the source action.

### Improvements:

* PasswordReset: rework PasswordReset to be a provider in it's own right - this means it has it's own routes, etc.

## [v0.4.1](https://github.com/team-alembic/ash_authentication/compare/v0.4.0...v0.4.1) (2022-11-03)




### Improvements:

* PasswordReset: A reset request is actually a query, not an update. (#23)

## [v0.4.0](https://github.com/team-alembic/ash_authentication/compare/v0.3.0...v0.4.0) (2022-11-02)




### Features:

* PasswordReset: allow users to request and reset their password. (#22)

## [v0.3.0](https://github.com/team-alembic/ash_authentication/compare/v0.2.1...v0.3.0) (2022-10-31)




### Features:

* Ash.PlugHelpers: Support standard actor configuration. (#16)

* Ash.PlugHelpers: Support standard actor configuration.

### Improvements:

* docs: change all references to `actor` to `user`.

## [v0.2.1](https://github.com/team-alembic/ash_authentication/compare/v0.2.0...v0.2.1) (2022-10-26)




### Bug Fixes:

* deprecation warnings caused by use of `Macro.expand_literal/2`.

### Improvements:

* move subject_name uniqueness validation to compile time.

* remove `generated: true` from macros.

## [v0.2.0](https://github.com/team-alembic/ash_authentication/compare/v0.1.0...v0.2.0) (2022-10-24)




### Features:

* PasswordAuthentication: Registration and authentication with local credentials (#4)

## [v0.1.0](https://github.com/team-alembic/ash_authentication/compare/v0.1.0...v0.1.0) (2022-09-27)



