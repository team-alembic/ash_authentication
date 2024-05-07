defmodule AshAuthentication.Strategy.Google.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.{Custom, OAuth2}

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    OAuth2.dsl()
    |> Map.merge(%{
      name: :google,
      args: [{:optional, :name, :google}],
      describe: """
      Provides a pre-configured authentication strategy for [Google](https://google.com/).

      This strategy is built using the `:oauth2` strategy, and thus provides all the same
      configuration options should you need them.

      ## More documentation:
      - The [Google OAuth 2.0 Overview](https://developers.google.com/identity/protocols/oauth2).
      - The [Google Tutorial](/documentation/tutorial/google.md)
      - The [OAuth2 documentation](`AshAuthentication.Strategy.OAuth2`)

      #### Strategy defaults:

      #{strategy_override_docs(Assent.Strategy.Google)}
      """,
      auto_set_fields: strategy_fields(Assent.Strategy.Google, icon: :google)
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
