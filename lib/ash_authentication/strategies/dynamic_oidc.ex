# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.DynamicOidc do
  alias __MODULE__.Dsl

  @moduledoc """
  Strategy for authenticating against arbitrary OpenID Connect providers
  whose configuration lives in a database table rather than in your
  application's compile-time DSL.

  This is the building block for B2B/multi-tenant SSO patterns: each row in
  your `OidcConnection` resource is one customer's IdP configuration
  (`base_url`, `client_id`, `client_secret`, plus optional UI metadata).
  At sign-in time the strategy queries the resource — typically scoped by
  the current Ash tenant — and runs the standard OIDC flow against the
  matched row.

  ## Setup

  First, define a connection resource using
  `AshAuthentication.OidcConnection`:

  ```elixir
  defmodule MyApp.Accounts.OidcConnection do
    use Ash.Resource,
      data_layer: AshPostgres.DataLayer,
      extensions: [AshAuthentication.OidcConnection],
      domain: MyApp.Accounts

    oidc_connection do
      domain MyApp.Accounts
    end

    postgres do
      table "oidc_connections"
      repo MyApp.Repo
    end
  end
  ```

  Then add the strategy to your user resource:

  ```elixir
  authentication do
    strategies do
      dynamic_oidc :sso do
        connection_resource MyApp.Accounts.OidcConnection
        identity_resource MyApp.Accounts.UserIdentity
        redirect_uri MyApp.Secrets
      end
    end
  end
  ```

  ## URL shape

  The strategy generates two routes:

    - `GET /<subject>/<strategy_name>/:connection_id/request` — initiate
      sign-in for a specific connection (the user/UI is responsible for
      knowing which connection_id to send to).
    - `GET /<subject>/<strategy_name>/callback` — single, shared callback
      URL. Each customer's IdP admin only ever needs to register *this*
      URL as their redirect URI. The connection_id is remembered between
      request and callback via the user's session.

  ## Tenant context

  If your connection resource is multitenant, the strategy will scope the
  lookup using the tenant set on the conn (`Ash.PlugHelpers.set_tenant/2`).
  Set the tenant **upstream** of the auth router — typically in a Phoenix
  plug that maps subdomain or header to your tenant. If no tenant is set
  and the resource is multitenant, the lookup will fail.

  Non-multitenant connection resources are also supported — the strategy
  simply queries globally.

  ## More documentation

  - `AshAuthentication.OidcConnection` — the resource extension this
    strategy depends on.
  - `AshAuthentication.Strategy.Oidc` — the underlying compile-time OIDC
    strategy. The runtime behaviour is identical aside from where the
    config comes from.
  """

  # The struct shape mirrors `AshAuthentication.Strategy.OAuth2` so the
  # existing OAuth2 plug helpers can operate on a populated DynamicOidc
  # value at request time. Compile-time DSL fills in the static config;
  # the plug fills in `base_url`, `client_id`, `client_secret` from the
  # matched connection row.
  # credo:disable-for-next-line Credo.Check.Warning.StructFieldAmount
  defstruct assent_strategy: Assent.Strategy.OIDC,
            auth_method: nil,
            authorization_params: [],
            authorize_url: nil,
            base_url: nil,
            client_authentication_method: "client_secret_basic",
            client_id: nil,
            client_secret: nil,
            code_verifier: false,
            connection_resource: nil,
            icon: :oidc,
            id_token_signed_response_alg: "RS256",
            id_token_ttl_seconds: nil,
            identity_relationship_name: :identities,
            identity_relationship_user_id_attribute: :user_id,
            identity_resource: false,
            name: nil,
            nonce: true,
            openid_configuration: nil,
            openid_configuration_uri: "/.well-known/openid-configuration",
            prevent_hijacking?: true,
            private_key: nil,
            private_key_id: nil,
            private_key_path: nil,
            provider: :dynamic_oidc,
            redirect_uri: nil,
            register_action_name: nil,
            registration_enabled?: true,
            resource: nil,
            session_identifier: :unsafe,
            sign_in_action_name: nil,
            site: nil,
            strategy_module: __MODULE__,
            team_id: nil,
            token_url: nil,
            trusted_audiences: nil,
            user_url: nil,
            # Set by the plug at request/callback time. Carried on the
            # struct so `DynamicOidc.IdentityChange` can read it without
            # plumbing it through action arguments.
            __connection_id__: nil,
            __spark_metadata__: nil

  alias AshAuthentication.Strategy.{Custom, DynamicOidc}

  use Custom, entity: Dsl.dsl()

  @type t :: %__MODULE__{
          assent_strategy: module,
          authorization_params: keyword | {module, keyword},
          client_authentication_method: nil | binary,
          connection_resource: module,
          icon: atom,
          id_token_signed_response_alg: binary,
          id_token_ttl_seconds: nil | pos_integer(),
          identity_relationship_name: atom,
          identity_relationship_user_id_attribute: atom,
          identity_resource: module | false,
          name: atom,
          nonce: boolean | nil | binary | {module, keyword},
          openid_configuration: nil | map,
          openid_configuration_uri: nil | binary | {module, keyword},
          prevent_hijacking?: boolean,
          provider: atom,
          redirect_uri: nil | binary | {module, keyword},
          register_action_name: atom,
          registration_enabled?: boolean,
          resource: module,
          session_identifier: nil | :unsafe | :jti,
          sign_in_action_name: atom,
          strategy_module: module,
          trusted_audiences: nil | [String.t()] | {module, keyword},
          __spark_metadata__: Spark.Dsl.Entity.spark_meta()
        }

  defdelegate transform(strategy, dsl_state), to: DynamicOidc.Transformer
  defdelegate verify(strategy, dsl_state), to: DynamicOidc.Verifier
end
