defmodule AshAuthentication.Strategy.Auth0.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.{Custom, OAuth2}

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    OAuth2.dsl()
    |> Map.merge(%{
      name: :auth0,
      args: [{:optional, :name, :auth0}],
      describe: """
      Provides a pre-configured authentication strategy for [Auth0](https://auth0.com/).

      This strategy is built using the `:oauth2` strategy, and thus provides all the same
      configuration options should you need them.

      For more information see the [Auth0 Quick Start Guide](/documentation/tutorials/auth0-quickstart.md)
      in our documentation.

      #### Strategy defaults:

      #{strategy_override_docs(Assent.Strategy.Auth0)}

      #### Schema:
      """,
      auto_set_fields: strategy_fields(Assent.Strategy.Auth0, icon: :auth0)
    })
  end

  defp strategy_fields(strategy, params) do
    []
    |> strategy.default_config()
    |> Keyword.put(:assent_strategy, strategy)
    |> Keyword.merge(params)
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
