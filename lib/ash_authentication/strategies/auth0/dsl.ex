# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Auth0.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.{Custom, Oidc}
  alias Assent.Strategy.Auth0

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    Oidc.dsl()
    |> Map.merge(%{
      name: :auth0,
      args: [{:optional, :name, :auth0}],
      describe: """
      Provides a pre-configured authentication strategy for [Auth0](https://auth0.com/).

      This strategy is built using the `:oidc` strategy, and automatically
      retrieves configuration from Auth0's discovery endpoint.

      #### More documentation:
      - The [Auth0 Tutorial](/documentation/tutorial/auth0.md).
      - The [OIDC documentation](`AshAuthentication.Strategy.Oidc`)

      #### Strategy defaults:

      #{strategy_override_docs(Auth0)}
      """,
      auto_set_fields: [assent_strategy: Auth0, icon: :auth0]
    })
    |> Custom.set_defaults(Auth0.default_config([]))
    |> Custom.set_defaults(trust_email_verified?: true)
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
