<!--
SPDX-FileCopyrightText: 2022 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# Microsoft Tutorial

This is a quick tutorial on how to configure Microsoft (Azure AD) authentication.

First you'll need a registered application in the [Microsoft Entra admin center](https://entra.microsoft.com/), in order to get your OAuth 2.0 credentials.

1. Under the **Entra ID** fan click **App registrations**
2. Click **New registration**
3. Enter a name for your application
4. Under **Redirect URI**, select **Web** and enter your callback URL. E.g. `http://localhost:4000/auth/user/microsoft/callback`
5. Click **Register**
6. From the app's **Overview** page, copy the **Application (client) ID** — this is your `client_id`
7. From the same **Overview** page, copy the **Directory (tenant) ID** — you'll need this if you want to restrict sign-in to a specific tenant
8. Navigate to **Certificates & secrets** > **+ New client secret**, add a description and expiry, then copy the secret **Value** — this is your `client_secret`

Next we configure our resource to use Microsoft credentials:

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
      microsoft do
        client_id MyApp.Secrets
        redirect_uri MyApp.Secrets
        client_secret MyApp.Secrets
      end
    end
  end
end
```

By default the strategy uses the `common` tenant endpoint, which allows any Microsoft
account (personal, work, or school). To restrict sign-in to a specific Azure tenant,
override `base_url`:

```elixir
microsoft do
  client_id MyApp.Secrets
  redirect_uri MyApp.Secrets
  client_secret MyApp.Secrets
  base_url "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0"
end
```

Please check the [guide](https://hexdocs.pm/ash_authentication/AshAuthentication.Secret.html) on how to properly configure your Secrets.
Then we need to define an action that will handle the oauth2 flow, for the Microsoft case it is `:register_with_microsoft` — it will handle both cases for our resource, user registration & login.

```elixir
defmodule MyApp.Accounts.User do
  require Ash.Resource.Change.Builtins
  use Ash.Resource,
    extensions: [AshAuthentication],
    domain: MyApp.Accounts

  # ...
  actions do
    create :register_with_microsoft do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      upsert? true
      upsert_identity :unique_email

      change AshAuthentication.GenerateTokenChange

      # Required if you have the `identity_resource` configuration enabled.
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
