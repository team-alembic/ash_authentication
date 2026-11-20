# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Microsoft.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.{Custom, Oidc}
  alias AshAuthentication.Strategy.Microsoft.AzureADMultitenant

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    Oidc.dsl()
    |> Map.merge(%{
      name: :microsoft,
      args: [{:optional, :name, :microsoft}],
      describe: """
      Provides a pre-configured authentication strategy for [Microsoft](https://microsoft.com/).

      This strategy is built using the `:oidc` strategy, and automatically
      validates tokens using Microsoft's tenant-specific discovery endpoint
      (`https://login.microsoftonline.com/{tenant}/v2.0/.well-known/openid-configuration`).

      By default the strategy uses the `common` tenant endpoint. To restrict
      sign-in to a specific Azure tenant, use its directory UUID in `base_url`.
      Verified tenant domains are not supported:

          base_url "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0"

      PKCE (`code_verifier`) is enabled by default, as recommended by Microsoft.
      Set `code_verifier false` to disable it.

      #### More documentation:
      - The [Microsoft OpenID Connect Overview](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc)
      - The [Microsoft Tutorial](/documentation/tutorials/microsoft.md)
      - The [OIDC documentation](`AshAuthentication.Strategy.Oidc`)

      #### Strategy defaults:

      #{strategy_override_docs()}
      """,
      auto_set_fields: [icon: :microsoft, assent_strategy: AzureADMultitenant]
    })
    |> Custom.set_defaults(dsl_defaults())
    |> Custom.set_defaults(code_verifier: true)
  end

  # Tenant-specific runtime defaults are derived from the configured base_url,
  # not frozen to the common tenant when Spark builds the strategy.
  defp dsl_defaults do
    AzureADMultitenant.default_config([])
    |> Keyword.drop([:tenant_id, :openid_configuration])
  end

  defp strategy_override_docs do
    defaults =
      dsl_defaults()
      |> Enum.map_join(
        ".\n",
        fn {key, value} ->
          "  * `#{inspect(key)}` is set to `#{inspect(value)}`"
        end
      )

    """
    The following defaults are applied:

    #{defaults}.
    """
  end
end
