# AshAuthentication

<img src="https://github.com/ash-project/ash/blob/main/logos/ash-auth-logo.svg?raw=true" alt="Ash Authentication Logo" width="250"/>

![Elixir CI](https://github.com/team-alembic/ash_authentication/workflows/Elixir%20Library/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Hex version badge](https://img.shields.io/hexpm/v/ash_authentication.svg)](https://hex.pm/packages/ash_authentication)

AshAuthentication provides drop-in support for user authentication for users of
the [Ash framework](https://ash-hq.org).  It is designed to be highly
configurable, with sensible defaults covering the most common use-cases.

## Warning

This software is not in beta, but it is still relatively young, and authentication is a very critical flow in any application, that touches on many aspects of security. We highly encourage considering how you configure this package very carefully, and testing its behavior in your own application. Those tests will also help ensure that any custom behavior you implement by modifying your resources does not break your authentication flows. Even though we do our best to prevent that situation with compile time validations, its not always possible.

## Installation

The package can be installed by adding `ash_authentication` to your list of
dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ash_authentication, "~> 3.6.1"}
  ]
end
```

## Usage

This package assumes that you have [Ash](https://ash-hq.org/) installed and
configured.  See the Ash documentation for details.

Once installed you can easily add support for authentication by adding the
`AshAuthentication` extension to your resource:

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    extensions: [AshAuthentication]

  attributes do
    uuid_primary_key :id
    attribute :email, :ci_string, allow_nil?: false
    attribute :hashed_password, :string, allow_nil?: false, sensitive?: true
  end

  authentication do
    api MyApp.Accounts

    strategies do
      password :password do
        identity_field :email
        hashed_password_field :hashed_password
      end
    end
  end

  identities do
    identity :unique_email, [:email]
  end
end
```

If you plan on providing authentication via the web, then you will need to
define a plug using
[`AshAuthentication.Plug`](https://team-alembic.github.io/ash_authentication/AshAuthentication.Plug.html)
which builds a [`Plug.Router`](https://hexdocs.pm/plug/Plug.Router.html) that
routes incoming authentication requests to the correct provider and provides
callbacks for you to manipulate the conn after success or failure.

If you're using AshAuthentication with Phoenix, then check out
[`ash_authentication_phoenix`](https://github.com/team-alembic/ash_authentication_phoenix)
which provides route helpers, a controller abstraction and LiveView components
for easy set up.

## Authentication Strategies

Currently supported strategies:

  1. [`AshAuthentication.Strategy.Password`](https://team-alembic.github.io/ash_authentication/AshAuthentication.Strategy.Password.html)
     - authenticate users against your local database using a unique identity
     (such as username or email address) and a password.
  2. [`AshAuthentication.Strategy.OAuth2`](https://team-alembic.github.io/ash_authentication/AshAuthentication.Strategy.OAuth2.html)
     - authenticate using local or remote [OAuth 2.0](https://oauth.net/2/)
     compatible services.

## Documentation

Documentation for the latest release will be [available on
hexdocs](https://hexdocs.pm/ash_authentication) and for the [`main`
branch](https://team-alembic.github.io/ash_authentication).

Additional support can be found on the [GitHub discussions
page](https://github.com/team-alembic/ash_authentication/discussions) and the
[Ash Discord](https://discord.gg/D7FNG2q).

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
