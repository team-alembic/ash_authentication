# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Google.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.{Custom, OAuth2}
  alias Assent.Strategy.Google

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

      #{strategy_override_docs(Google)}
      """,
      auto_set_fields: [icon: :google, assent_strategy: Google]
    })
    |> Custom.set_defaults(
      base_url: "https://www.googleapis.com",
      authorize_url: "https://accounts.google.com/o/oauth2/v2/auth",
      token_url: "/oauth2/v4/token",
      user_url: "/oauth2/v3/userinfo",
      authorization_params: [
        scope:
          "https://www.googleapis.com/auth/userinfo.email https://www.googleapis.com/auth/userinfo.profile"
      ],
      auth_method: :client_secret_post
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
