<!--
SPDX-FileCopyrightText: 2022 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# Google Tutorial

This is a quick tutorial on how to configure Google authentication.

First you'll need a registered application in [Google Cloud](https://console.cloud.google.com/welcome), in order to get your OAuth 2.0 Client credentials.

1. On the Cloud's console **Quick access** section select **APIs & Services**, then **Credentials**
2. Click on **+ CREATE CREDENTIALS** and from the dropdown select **OAuth client ID**
3. From the google developers console, we will need: `client_id` & `client_secret`
4. Enter your callback uri under **Authorized redirect URIs**. E.g. `http://localhost:4000/auth/user/google/callback`.

Next we configure our resource to use google credentials:

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    extensions: [AshAuthentication],
    domain: MyApp.Accounts

  attributes do
    ...
  end

  authentication do
    strategies do
      google do
        client_id MyApp.Secrets
        redirect_uri MyApp.Secrets
        client_secret MyApp.Secrets
        identity_resource MyApp.Accounts.UserIdentity
      end
    end
  end
end
```

Please check the [guide](https://hexdocs.pm/ash_authentication/AshAuthentication.Secret.html) on how to properly configure your Secrets.

## The user identity resource

OAuth2-based strategies require an `identity_resource` - a resource that stores
the provider's `iss` (issuer) and `sub` (subject) claims for each linked
account. Matching a returning user by their email address (or any other claim)
is **not** safe: per the OpenID Connect specification only the `iss`/`sub`
combination uniquely and stably identifies an end-user. The identity resource is
where those values live.

Add a `UserIdentity` resource using the `AshAuthentication.UserIdentity`
extension. There is no need to define any attributes - the extension generates
them for you.

```elixir
defmodule MyApp.Accounts.UserIdentity do
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.UserIdentity],
    domain: MyApp.Accounts

  user_identity do
    user_resource MyApp.Accounts.User
  end

  # Configure your data layer as appropriate for your application.
  postgres do
    table "user_identities"
    repo MyApp.Repo
  end
end
```

Don't forget to add it to your domain, and to generate and run migrations for
the new resource.

```bash
mix ash.codegen add_user_identities
mix ash.migrate
```

Then we need to define an action that will handle the oauth2 flow, for the google case it is `:register_with_google` it will handle both cases for our resource, user registration & login.

```elixir
defmodule MyApp.Accounts.User do
  require Ash.Resource.Change.Builtins
  use Ash.Resource,
    extensions: [AshAuthentication],
    domain: MyApp.Accounts

  # ...
  actions do
    create :register_with_google do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      upsert? true
      upsert_identity :unique_email

      change AshAuthentication.GenerateTokenChange

      # Required: persists the provider's `iss`/`sub` identity claims.
      change AshAuthentication.Strategy.OAuth2.IdentityChange

      change fn changeset, _ ->
        user_info = Ash.Changeset.get_argument(changeset, :user_info)

        Ash.Changeset.change_attributes(changeset, Map.take(user_info, ["email"]))
      end

      # Required if you're using the password & confirmation strategies
      upsert_fields []
      change set_attribute(:confirmed_at, &DateTime.utc_now/0)
    end
  end

  # ...

end
```

Ensure you set the `hashed_password` to `allow_nil?` if you are also using the password strategy.

```elixir
defmodule MyApp.Accounts.User do
  # ...
  attributes do
    # ...
    attribute :hashed_password, :string, allow_nil?: true, sensitive?: true
  end
  # ...
end
```

And generate and run migrations in that case.

```bash
mix ash.codegen make_hashed_password_nullable
mix ash.migrate
```
