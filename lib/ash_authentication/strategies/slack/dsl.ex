# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Slack.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.{Custom, Oidc}
  alias Assent.Strategy.Slack

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    secret_type = AshAuthentication.Dsl.secret_type()

    Oidc.dsl()
    |> Map.merge(%{
      name: :slack,
      args: [{:optional, :name, :slack}],
      describe: """
      Provides a pre-configured authentication strategy for [Slack](https://slack.com/).

      This strategy is built using the `:oauth2` strategy, and thus provides all the same
      configuration options should you need them.

      #### More documentation:
      - The [Slack Tutorial](/documentation/tutorial/slack.md).
      - The [OIDC documentation](`AshAuthentication.Strategy.Oidc`)

      #### Strategy defaults:

      #{strategy_override_docs(Slack)}
      """,
      auto_set_fields: [icon: :slack, assent_strategy: Slack]
    })
    |> Custom.set_defaults(Slack.default_config([]))
    |> Map.update!(
      :schema,
      fn schema ->
        schema
        |> Keyword.put(:team_id,
          type: secret_type,
          required: false,
          doc: "The team id to restrict authorization for."
        )
        |> Keyword.drop([:authorize_url])
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
