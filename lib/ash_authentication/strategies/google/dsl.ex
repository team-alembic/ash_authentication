# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Google.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.{Custom, Oidc}
  alias Assent.Strategy.Google

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    Oidc.dsl()
    |> Map.merge(%{
      name: :google,
      args: [{:optional, :name, :google}],
      describe: """
      Provides a pre-configured authentication strategy for [Google](https://google.com/).

      This strategy is built using the `:oidc` strategy, and automatically
      retrieves configuration from Google's discovery endpoint.

      ## More documentation:
      - The [Google OpenID Connect Overview](https://developers.google.com/identity/openid-connect/openid-connect).
      - The [Google Tutorial](/documentation/tutorial/google.md)
      - The [OIDC documentation](`AshAuthentication.Strategy.Oidc`)

      #### Strategy defaults:

      #{strategy_override_docs(Google)}
      """,
      auto_set_fields: [icon: :google, assent_strategy: Google]
    })
    |> Custom.set_defaults(Google.default_config([]))
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
