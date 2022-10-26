# AshAuthentication

AshAuthentication provides drop-in support for user authentication for users of
the [Ash framework](https://ash-hq.org).  It is designed to be highly
configurable, with sensible defaults covering the most common use-cases.

## Installation

The package can be installed by adding `ash_authentication` to your list of
dependencies in `mix.exs`:

```elixir
def deps do
  [
    {:ash_authentication, "~> 0.2.1"}
  ]
end
```

## Usage

This package assumes that you have [Phoenix](https://phoenixframework.org/) and
[Ash](https://ash-hq.org/) installed and configured.  See their individual
documentation for details.

Once installed you can easily add support for authentication by configuring one
or more extensions onto your Ash resource:

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    extensions: [AshAuthentication, AshAuthentication.PasswordAuthentication]

  attributes do
    uuid_primary_key :id
    attribute :email, :ci_string, allow_nil?: false
    attribute :hashed_password, :string, allow_nil?: false, sensitive?: true
  end

  authentication do
    api MyApp.Accounts
  end

  password_authentication do
    identity_field :email
    hashed_password_field :hashed_password
  end

  identities do
    identity :unique_email, [:email]
  end
end
```

If you plan on providing authentication via the web, then you will need to
define a plug using
[`AshAuthentication.Plug`](https://team-alembic.github.io/ash_authentication/AshAuthentication.Plug.html)
which builds a [`Plug.Router`](https://hexdocs.pm/plug/Plug.Router.html) which
routes incoming authentication requests to the correct provider and provides
callbacks for you to manipulate the conn after success or failure.

If you're using AshAuthentication with Phoenix, then check out
[`ash_authentication_phoenix`](https://github.com/team-alembic/ash_authentication_phoenix)
which provides route helpers, a controller abstraction and LiveView components
for easy set up.

## Authentication Providers

Currently the only supported authentication provider is
[`AshAuthentication.PasswordAuthentication`](https://team-alembic.github.io/ash_authentication/AshAuthentication.PasswordAuthentication.html)
which provides actions for registering and signing in users using an identifier
and a password.

Planned future providers include:

  * OAuth 1.0
  * OAuth 2.0
  * OpenID Connect

## Documentation

Documentation for the latest release will be [available on
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

