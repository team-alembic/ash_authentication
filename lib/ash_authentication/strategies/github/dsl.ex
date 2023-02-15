defmodule AshAuthentication.Strategy.Github.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.{Custom, OAuth2}

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    OAuth2.dsl()
    |> Map.merge(%{
      name: :github,
      args: [{:optional, :name, :github}],
      describe: """
      Provides a pre-configured authentication strategy for [GitHub](https://github.com/).

      This strategy is built using the `:oauth2` strategy, and thus provides all the same
      configuration options should you need them.

      For more information see the [Github Quick Start Guide](/documentation/tutorials/github-quickstart.md)
      in our documentation.

      #### Strategy defaults:

      #{strategy_override_docs(Assent.Strategy.Github)}

      #### Schema:
      """,
      auto_set_fields: strategy_fields(Assent.Strategy.Github, icon: :github)
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
