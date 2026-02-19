# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Microsoft.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.{Custom, Oidc}
  alias Assent.Strategy.AzureAD

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
      retrieves configuration from Microsoft's discovery endpoint
      (`https://login.microsoftonline.com/{tenant|common}/v2.0/.well-known/openid-configuration`).

      By default the strategy uses the `common` tenant endpoint. To restrict
      sign-in to a specific Azure tenant, override `base_url`:

          base_url "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0"

      #### More documentation:
      - The [Microsoft OpenID Connect Overview](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc)
      - The [Microsoft Tutorial](/documentation/tutorials/microsoft.md)
      - The [OIDC documentation](`AshAuthentication.Strategy.Oidc`)

      #### Strategy defaults:

      #{strategy_override_docs(AzureAD)}
      """,
      auto_set_fields: [icon: :microsoft, assent_strategy: AzureAD]
    })
    |> Custom.set_defaults(AzureAD.default_config([]))
    |> Map.update!(
      :schema,
      fn schema ->
        # Override response mode from form_post to avoid CSFR
        Keyword.update!(schema, :authorization_params, fn config ->
          Keyword.put(config, :default, scope: "email profile")
        end)
      end
    )
  end

  defp strategy_override_docs(strategy) do
    defaults =
      []
      |> strategy.default_config()
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
