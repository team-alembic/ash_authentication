# AshAuthentication

<img src="https://github.com/ash-project/ash/blob/main/logos/ash-auth-logo.svg?raw=true" alt="Ash Authentication Logo" width="250"/>

![Elixir CI](https://github.com/team-alembic/ash_authentication/workflows/Elixir%20Library/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Hex version badge](https://img.shields.io/hexpm/v/ash_authentication.svg)](https://hex.pm/packages/ash_authentication)

AshAuthentication provides drop-in support for user authentication for users of
the [Ash framework](https://ash-hq.org).  It is designed to be highly
configurable, with sensible defaults covering the most common use-cases.

## Warning

This is not beta software, but it is still relatively young, and authentication is a very critical flow in any application, that touches on many aspects of security. We highly encourage considering how you configure this package very carefully, and testing its behavior in your own application. Those tests will also help ensure that any custom behavior you implement by modifying your resources does not break your authentication flows. Even though we do our best to prevent that situation with compile time validations, its not always possible.

## Installation

The package can be installed by adding `ash_authentication` to your list of
dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ash_authentication, "~> 3.11.9"}
  ]
end
```

## Documentation

See the [official documentation](https://ash-hq.org/docs/guides/ash_authentication/latest/tutorials/getting-started-with-authentication) for more.

Additionally, documentation for the latest release will be [available on
hexdocs](https://hexdocs.pm/ash_authentication) and for the [`main`
branch](https://team-alembic.github.io/ash_authentication).

## Contributing

  * To contribute updates, fixes or new features please fork and open a
    pull-request against `main`.
  * Please use [conventional
    commits](https://www.conventionalcommits.org/en/v1.0.0/) - this allows us to
    dynamically generate the changelog.
  * Feel free to ask any questions on out [GitHub discussions
    page](https://github.com/team-alembic/ash_authentication/discussions).

## Licence

`AshAuthentication` is licensed under the terms of the [MIT
license](https://opensource.org/licenses/MIT).  See the [`LICENSE` file in this
repository](https://github.com/team-alembic/ash_authentication/blob/main/LICENSE)
for details.
