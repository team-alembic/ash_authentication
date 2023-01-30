defmodule AshAuthentication.Strategy.Github do
  @moduledoc """
  Strategy for authenticating using [GitHub](https://github.com)

  This strategy builds on-top of `AshAuthentication.Strategy.OAuth2` and
  [`assent`](https://hex.pm/packages/assent).

  In order to use GitHub you need to provide the following minimum configuration:

    - `client_id`
    - `redirect_uri`
    - `client_secret`

  See the [GitHub quickstart guide](/documentation/tutorials/github-quickstart.html)
  for more information.
  """

  alias AshAuthentication.Strategy.{Custom, OAuth2}
  use Custom

  @doc false
  # credo:disable-for-next-line Credo.Check.Warning.SpecWithStruct
  @spec dsl :: Custom.entity()
  def dsl do
    OAuth2.dsl()
    |> Map.merge(%{
      name: :github,
      args: [{:optional, :name, :github}],
      describe: """
      Provides a pre-configured authentication strategy for [GitHub](https://github.com/).

      This strategy is built using `:oauth2` strategy, and thus provides all the same
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

  defdelegate transform(strategy, dsl_state), to: OAuth2
  defdelegate verify(strategy, dsl_state), to: OAuth2

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
