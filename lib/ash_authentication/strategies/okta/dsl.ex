# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Okta.Dsl do
  @moduledoc false

  alias AshAuthentication.Strategy.{Custom, Oidc}

  # `Assent.Strategy.OIDC` automatically prepends `openid` to the scope at
  # request time, so it's omitted here.
  @defaults [authorization_params: [scope: "profile email"]]

  @doc false
  @spec dsl :: Custom.entity()
  def dsl do
    Oidc.dsl()
    |> Map.merge(%{
      name: :okta,
      args: [{:optional, :name, :okta}],
      describe: """
      Provides a pre-configured authentication strategy for [Okta](https://okta.com/).

      This strategy is built using the `:oidc` strategy, and automatically
      retrieves configuration from Okta's discovery endpoint
      (`{base_url}/.well-known/openid-configuration`).

      Set `base_url` to your Okta authorization server. For most installations
      that's `https://YOUR_OKTA_DOMAIN/oauth2/default` (the built-in `default`
      Custom Authorization Server).

      #### More documentation:
      - The [Okta OpenID Connect Overview](https://developer.okta.com/docs/concepts/oauth-openid/)
      - The [Okta Tutorial](/documentation/tutorials/okta.md)
      - The [OIDC documentation](`AshAuthentication.Strategy.Oidc`)

      #### Strategy defaults:

      #{strategy_override_docs(@defaults)}
      """,
      auto_set_fields: [icon: :okta, assent_strategy: Assent.Strategy.OIDC]
    })
    |> Custom.set_defaults(@defaults)
  end

  defp strategy_override_docs(defaults) do
    rendered =
      Enum.map_join(defaults, ".\n", fn {key, value} ->
        "  * `#{inspect(key)}` is set to `#{inspect(value)}`"
      end)

    """
    The following defaults are applied:

    #{rendered}.
    """
  end
end
