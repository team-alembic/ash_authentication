# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Auth0 do
  alias __MODULE__.Dsl

  @moduledoc """
  Strategy for authenticating using [Auth0](https://auth0.com).

  This strategy builds on-top of `AshAuthentication.Strategy.Oidc` and
  [`assent`](https://hex.pm/packages/assent).

  In order to use Auth0 you need to provide the following minimum configuration:

    - `client_id`
    - `redirect_uri`
    - `client_secret`
    - `base_url`

  As of Assent v0.3.0, the Auth0 strategy uses OpenID Connect (OIDC) and
  automatically retrieves configuration (token URL, user info URL, etc.) from
  Auth0's discovery endpoint.

  ## More documentation:
  - The [Auth0 Tutorial](/documentation/tutorial/auth0.md).
  - The [OIDC documentation](`AshAuthentication.Strategy.Oidc`)
  """

  alias AshAuthentication.Strategy.{Custom, Oidc}

  use Custom, entity: Dsl.dsl()

  defdelegate transform(strategy, dsl_state), to: Oidc
  defdelegate verify(strategy, dsl_state), to: Oidc
end
