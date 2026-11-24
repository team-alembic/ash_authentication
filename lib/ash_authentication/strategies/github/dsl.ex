# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Github.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.{Custom, OAuth2}
  alias Assent.Strategy.Github

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

      #### More documentation:
      - The [GitHub Tutorial](/documentation/tutorial/github.md).
      - The [OAuth2 documentation](`AshAuthentication.Strategy.OAuth2`)

      #### Strategy defaults:

      #{strategy_override_docs()}
      """,
      auto_set_fields: [icon: :github, assent_strategy: Github]
    })
    |> Custom.set_defaults(dsl_defaults())
    |> Custom.set_defaults(trust_email_verified?: true)
  end

  # Keep the public OAuth2 auth_method option overridable by applications.
  defp dsl_defaults do
    {method, defaults} = Keyword.pop(Github.default_config([]), :client_authentication_method)
    Keyword.put(defaults, :auth_method, method)
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
