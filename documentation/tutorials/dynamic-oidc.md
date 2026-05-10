<!--
SPDX-FileCopyrightText: 2022 Alembic Pty Ltd

SPDX-License-Identifier: MIT
-->

# Dynamic OIDC Tutorial

This is a quick tutorial on how to configure data-driven OpenID Connect — one
IdP per database row instead of one IdP per compile-time DSL block. It's the
building block for B2B/multi-tenant SSO: each customer brings their own Okta /
Entra ID / Auth0 / generic OIDC tenant, and you store their `base_url`,
`client_id`, and `client_secret` as a regular Ash resource.

If you only have a handful of IdPs known at compile time, prefer the static
[`oidc`](AshAuthentication.Strategy.Oidc.html), [`okta`](okta.md),
[`auth0`](auth0.md), or [`microsoft`](microsoft.md) strategies instead.

## Quick setup with Igniter

The fastest way to add dynamic OIDC is with the Igniter generator:

```bash
mix ash_authentication.add_strategy.dynamic_oidc
```

This generates an `OidcConnection` resource alongside your user resource, wires
a `dynamic_oidc :sso` strategy in, adds a `register_with_sso` action, and
prints follow-up instructions. The rest of this tutorial covers what's
happening — and the bits that the generator deliberately leaves to you
(multitenancy and secret encryption).

## Manual setup

### 1. Define the connection resource

The connection resource holds one row per customer / tenant IdP. Extend it with
`AshAuthentication.OidcConnection` and the extension will fill in default
attributes (`base_url`, `client_id`, `client_secret`, `display_name`,
`icon_url`) and a default `:read` action.

```elixir
defmodule MyApp.Accounts.OidcConnection do
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshAuthentication.OidcConnection],
    domain: MyApp.Accounts

  oidc_connection do
    domain MyApp.Accounts
    # All field names are configurable; defaults shown:
    # base_url_field :base_url
    # client_id_field :client_id
    # client_secret_field :client_secret
    # display_name_field :display_name
    # icon_url_field :icon_url
  end

  actions do
    defaults [:read, :destroy, create: :*, update: :*]
  end

  postgres do
    table "oidc_connections"
    repo MyApp.Repo
  end

  policies do
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end

    # ...your own policies for admin write operations
  end
end
```

The bypass is required: the strategy needs to read connection rows during the
OIDC flow, regardless of who's signed in (or not signed in) at that moment.

### 2. Add the strategy

```elixir
defmodule MyApp.Accounts.User do
  use Ash.Resource,
    extensions: [AshAuthentication],
    domain: MyApp.Accounts

  authentication do
    strategies do
      dynamic_oidc :sso do
        connection_resource MyApp.Accounts.OidcConnection
        identity_resource MyApp.Accounts.UserIdentity
        redirect_uri MyApp.Secrets
      end
    end
  end
end
```

`base_url`, `client_id`, and `client_secret` are intentionally *not* part of
the strategy DSL — they're loaded at request time from the matched connection
row. Everything else (`authorization_params`, `nonce`,
`id_token_signed_response_alg`, etc.) is identical to the
[`oidc`](AshAuthentication.Strategy.Oidc.html) strategy.

`identity_resource` is optional but recommended once you have more than one
IdP: it lets one user link multiple identities, and
`DynamicOidc.IdentityChange` (see below) namespaces those identities by
`connection_id` so two IdPs that happen to issue the same `sub` claim don't
collide.

### 3. Define the register action

```elixir
actions do
  create :register_with_sso do
    argument :user_info, :map, allow_nil?: false
    argument :oauth_tokens, :map, allow_nil?: false
    upsert? true
    upsert_identity :unique_email

    change AshAuthentication.GenerateTokenChange

    # IMPORTANT: use the dynamic-aware IdentityChange, not the OAuth2 one.
    # It namespaces the identity's `strategy` field with the matched
    # connection_id so per-IdP identities stay distinct.
    change AshAuthentication.Strategy.DynamicOidc.IdentityChange

    change {AshAuthentication.Strategy.OAuth2.UserInfoToAttributes, fields: [:email]}
  end
end
```

> #### Why the dynamic-aware change? {: .info}
>
> `OAuth2.IdentityChange` writes the strategy name verbatim into the identity's
> `strategy` field. With multiple `dynamic_oidc` connections that all share
> one strategy name, two IdPs issuing the same `sub` would collide on the
> `{user_id, uid, strategy}` unique constraint. `DynamicOidc.IdentityChange`
> namespaces the value as `"<strategy_name>/<connection_id>"`, keeping
> per-IdP identities distinct.

If you also use the password strategy, ensure `hashed_password` is nullable:

```elixir
attribute :hashed_password, :string, allow_nil?: true, sensitive?: true
```

```bash
mix ash.codegen make_hashed_password_nullable
mix ash.migrate
```

## URL shape

The strategy generates two routes:

  - `GET /:subject/:strategy_name/:connection_id/request` — initiate sign-in for a specific connection.
  - `GET /:subject/:strategy_name/callback` — single shared callback URL.

For the example above (subject `user`, strategy `sso`):

```
GET /auth/user/sso/<connection-uuid>/request
GET /auth/user/sso/callback
```

Each customer's IdP admin only ever needs to register that one shared callback
URL in their app integration. The connection id is remembered between request
and callback in the user's session.

## Multitenancy

The strategy will scope connection lookups by the current Ash tenant when your
connection resource is multitenant. Make sure the tenant is set **upstream of
the auth router** — typically in a Phoenix plug that maps subdomain or header
to your tenant:

```elixir
# lib/my_app_web/plugs/set_tenant_from_subdomain.ex
defmodule MyAppWeb.Plugs.SetTenantFromSubdomain do
  import Plug.Conn

  def init(opts), do: opts

  def call(conn, _opts) do
    case conn.host |> String.split(".") do
      [tenant, _domain, _tld] -> Ash.PlugHelpers.set_tenant(conn, tenant)
      _ -> conn
    end
  end
end
```

```elixir
# lib/my_app_web/router.ex
pipeline :browser do
  # ...
  plug MyAppWeb.Plugs.SetTenantFromSubdomain
  plug :load_from_session
end
```

Non-multitenant connection resources are also supported — the strategy simply
queries globally. That's a fine choice when you have a single deployment with
multiple IdPs but no per-customer isolation.

## Secret storage

Storing `client_secret` as a plaintext string is convenient but dangerous — a
database compromise leaks every customer's IdP credentials. Encrypt it at rest
with [`ash_cloak`](https://hexdocs.pm/ash_cloak), then expose a calculation
that decrypts on load:

```elixir
defmodule MyApp.Accounts.OidcConnection do
  use Ash.Resource,
    extensions: [AshAuthentication.OidcConnection, AshCloak],
    # ...

  oidc_connection do
    domain MyApp.Accounts
    client_secret_field :decrypted_client_secret
  end

  cloak do
    vault MyApp.Vault
    attributes [:client_secret]
    decrypt_by_default [:client_secret]
  end

  calculations do
    calculate :decrypted_client_secret, :string, expr(client_secret)
  end
end
```

Any field on the resource — attribute, calculation, or aggregate — can back any
`*_field` configuration option, so you have full flexibility over how the value
is sourced.

## Sign-in UI (ash_authentication_phoenix)

If you're using
[ash_authentication_phoenix](https://hexdocs.pm/ash_authentication_phoenix),
the `SignIn` LiveView automatically renders the
`AshAuthentication.Phoenix.Components.DynamicOidc` component for any
`dynamic_oidc` strategy on your resource. It queries the `connection_resource`
at render time (forwarding the current Ash tenant) and renders one sign-in
button per matched row.

  - `display_name` drives the button label, falling back to the host portion of
    `base_url` if unset.
  - `icon_url` drives the icon, falling back to a generic SSO SVG if unset.
  - If no rows match the current tenant, no buttons are rendered — the strategy
    effectively goes dormant for that tenant.

That means your customer-facing UI is just: ensure
`Ash.PlugHelpers.set_tenant/2` runs upstream of the LiveView mount, and the
right buttons show up.

## Connection-management UI

The connection resource is just an Ash resource — actions, relationships,
policies, validations all work as you'd expect. The typical pattern is:

  - Admin UI for *your* staff: full CRUD over connections, scoped by tenant.
  - Self-service UI for tenant admins: scoped CRUD where they can manage only
    their own tenant's IdPs.
  - Validation: smoke-test a connection's `base_url` resolves an
    `openid-configuration` document before letting an admin save it (call
    `Assent.Strategy.OIDC.fetch_openid_configuration/1` from a custom action).

There's nothing AshAuthentication-specific about that surface — it's the
resource you defined in step 1.

## More documentation

  - `AshAuthentication.Strategy.DynamicOidc` — runtime details of the strategy.
  - `AshAuthentication.OidcConnection` — the resource extension used here.
  - [Custom Strategy](custom-strategy.md) — if you need a different shape
    entirely (e.g. dynamic SAML), the dynamic_oidc strategy is itself a worked
    example.
