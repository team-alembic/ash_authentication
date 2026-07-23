# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.DynamicOidc.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.{Custom, DynamicOidc, Oidc}

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    Oidc.dsl()
    |> Map.merge(%{
      name: :dynamic_oidc,
      target: DynamicOidc,
      args: [{:optional, :name, :dynamic_oidc}],
      describe: """
      An OpenID Connect strategy whose connection details (`base_url`,
      `client_id`, `client_secret`) are loaded at request time from a
      database resource extended with `AshAuthentication.OidcConnection`.

      This is the building block for data-driven multi-tenant SSO: each row
      in the connection resource is one customer's IdP configuration, and
      the strategy looks up the right row based on the request path
      (`:connection_id` segment) plus the current Ash tenant.

      #### More documentation:
      - `AshAuthentication.OidcConnection` — the resource extension this strategy depends on
      - `AshAuthentication.Strategy.Oidc` — the underlying compile-time OIDC strategy
      """,
      auto_set_fields: [
        assent_strategy: Assent.Strategy.OIDC,
        icon: :oidc,
        provider: :dynamic_oidc
      ],
      schema: patch_schema()
    })
  end

  defp patch_schema do
    Oidc.dsl()
    |> Map.get(:schema, [])
    # `base_url`, `client_id`, and `client_secret` come from the connection
    # resource, not from compile-time DSL.
    |> Keyword.delete(:base_url)
    |> Keyword.delete(:client_id)
    |> Keyword.delete(:client_secret)
    # `private_key`-related fields (used for `private_key_jwt` client auth)
    # could in theory live on the connection too, but for now we don't
    # support them — the typical Okta/Entra/Auth0 setup uses
    # `client_secret_basic`.
    |> Keyword.delete(:private_key)
    |> Keyword.delete(:private_key_id)
    |> Keyword.delete(:private_key_path)
    # `idp_initiated_login?` is inherited from the OAuth2 schema but cannot
    # work here (see `DynamicOidc.Verifier`, which rejects it at compile
    # time): the restart it triggers resolves provider config from a
    # `connection_id` in the request path, which an IdP-initiated callback
    # does not carry. Keep the option in the schema so the verifier can return
    # a helpful error, but override its docs so generated references describe
    # the rejection rather than inheriting OAuth2's "this works" text.
    |> Keyword.put(:idp_initiated_login?,
      type: :boolean,
      default: false,
      doc:
        "Not supported on `dynamic_oidc` and rejected at compile time: an " <>
          "IdP-initiated callback carries no `connection_id`, so the " <>
          "request-phase restart cannot resolve the connection's provider " <>
          "config. Use a statically-configured `oauth2`/`oidc` strategy for " <>
          "IdP-initiated login."
    )
    |> Keyword.merge(
      connection_resource: [
        type: {:behaviour, Ash.Resource},
        doc: """
        The Ash resource (extended with `AshAuthentication.OidcConnection`)
        that stores per-tenant OIDC client configuration.
        """,
        required: true
      ],
      authorization_params: [
        type: AshAuthentication.Dsl.secret_keyword_type(),
        doc:
          "Any additional parameters to encode in the request phase. eg: `authorization_params scope: \"openid profile email\"`",
        default: [scope: "profile email"]
      ]
    )
  end
end
