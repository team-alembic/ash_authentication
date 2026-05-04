<!--
SPDX-FileCopyrightText: 2022 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# Okta Tutorial

This is a quick tutorial on how to configure [Okta](https://okta.com) authentication.

## Quick setup with Igniter

The fastest way to add Okta authentication is with the Igniter generator:

```bash
mix ash_authentication.add_strategy okta
```

This creates the `UserIdentity` resource, register action, secrets wiring, and strategy DSL for you. Follow the printed instructions to register your Okta application and set the required environment variables. The rest of this tutorial covers manual setup.

## Manual setup

First you'll need a registered application in your [Okta Admin Console](https://login.okta.com/) to get your OAuth 2.0 credentials.

1. In the Admin Console, go to **Applications > Applications**
2. Click **Create App Integration**
3. Choose **OIDC - OpenID Connect** as the sign-in method, and **Web Application** as the application type, then click **Next**
4. Give the app a name
5. Under **Sign-in redirect URIs**, add your callback URL — e.g. `http://localhost:4000/auth/user/okta/callback`
6. Choose which Okta users should have access (assignments) and click **Save**
7. From the app's **General** tab, copy the **Client ID** and **Client secret**

You'll also need your Okta domain (e.g. `mycompany.okta.com`) — visible in the Admin Console URL — and an authorization server. Most installations should use the built-in `default` Custom Authorization Server: combined, your `base_url` is `https://mycompany.okta.com/oauth2/default`.

> #### Org vs Custom Authorization Server {: .info}
>
> Okta exposes two kinds of authorization servers:
>
> - **Custom Authorization Server** (recommended) — issuer is `https://YOUR_OKTA_DOMAIN/oauth2/{authServerId}`. Every Okta org ships with one named `default`. Configure claims, scopes, and policies under **Security > API > Authorization Servers**.
> - **Org Authorization Server** — issuer is `https://YOUR_OKTA_DOMAIN`. Only suitable for a small number of Okta-internal use cases.
>
> If you're not sure, use the `default` Custom Authorization Server.

Next we configure our resource to use Okta credentials:

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    extensions: [AshAuthentication],
    domain: MyApp.Accounts

  attributes do
    # ...
  end

  authentication do
    strategies do
      okta do
        client_id MyApp.Secrets
        client_secret MyApp.Secrets
        redirect_uri MyApp.Secrets
        base_url MyApp.Secrets
      end
    end
  end
end
```

Please check the [guide](https://hexdocs.pm/ash_authentication/AshAuthentication.Secret.html) on how to properly configure your Secrets. The `base_url` should resolve to something like `https://mycompany.okta.com/oauth2/default`.

Then we need to define the action that will handle the OIDC flow. For Okta the action is `:register_with_okta` — it handles both registration of new users and sign-in for existing ones.

```elixir
defmodule MyApp.Accounts.User do
  require Ash.Resource.Change.Builtins
  use Ash.Resource,
    extensions: [AshAuthentication],
    domain: MyApp.Accounts

  # ...
  actions do
    create :register_with_okta do
      argument :user_info, :map, allow_nil?: false
      argument :oauth_tokens, :map, allow_nil?: false
      upsert? true
      upsert_identity :unique_email

      change AshAuthentication.GenerateTokenChange

      # Required if you have the `identity_resource` configuration enabled.
      change AshAuthentication.Strategy.OAuth2.IdentityChange

      change {AshAuthentication.Strategy.OAuth2.UserInfoToAttributes, fields: [:email]}

      # Required if you're using the password & confirmation strategies
      upsert_fields []
      change set_attribute(:confirmed_at, &DateTime.utc_now/0)
    end
  end

  # ...
end
```

Ensure you set `hashed_password` to `allow_nil?: true` if you are also using the password strategy:

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

Then generate and run migrations:

```bash
mix ash.codegen make_hashed_password_nullable
mix ash.migrate
```

## Working with Okta groups

If you've configured your authorization server to include a `groups` claim (under **Security > API > Authorization Servers > {server} > Claims**), the claim will appear in the `user_info` argument passed to your `register_with_okta` action.

The shape of the value depends on the claim's configuration:

- When the claim's value type is **Groups** with a "Matches regex" / "Starts with" / "Equals" filter, Okta returns a JSON array of group names.
- When the claim's value type is **Expression** returning a single string, Okta returns a string.

Normalise both shapes before pattern-matching — e.g. wrap with `List.wrap/1`:

```elixir
groups = user_info |> Map.get("groups", []) |> List.wrap()
```

For full user/group sync (provisioning users from Okta and keeping group membership in step), prefer SCIM over driving everything off the OIDC `groups` claim — the claim is only populated when a user signs in, and won't catch group changes made while the user is already authenticated.

## Step-up authentication / MFA

To force re-authentication, request specific factors, or pass other Okta-specific authorization parameters, use `authorization_params`. The `acr_values` to pass depend on which Okta engine your org runs:

```elixir
okta do
  # ...
  authorization_params prompt: "login"
end
```

```elixir
# Okta Identity Engine (default for tenants created since 2022):
okta do
  # ...
  authorization_params acr_values: "urn:okta:loa:2fa:any:ifpossible"
end
```

```elixir
# Okta Classic Engine only:
okta do
  # ...
  authorization_params acr_values: "urn:okta:loa:2fa:any"
end
```

See [Okta's step-up authentication guide](https://developer.okta.com/docs/guides/step-up-authentication/) for the current ACR value catalog and engine differences.
