# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Google do
  alias __MODULE__.Dsl

  @moduledoc """
  Strategy for authenticating using [Google](https://google.com)

  This strategy builds on-top of `AshAuthentication.Strategy.Oidc` and
  [`assent`](https://hex.pm/packages/assent).

  In order to use Google you need to provide the following minimum configuration:

    - `client_id`
    - `redirect_uri`
    - `client_secret`

  As of Assent v0.3.0, the Google strategy uses OpenID Connect (OIDC) and
  automatically retrieves configuration (token URL, user info URL, etc.)
  from Google's discovery endpoint.

  ## More documentation:
  - The [Google OpenID Connect Overview](https://developers.google.com/identity/openid-connect/openid-connect).
  - The [Google Tutorial](/documentation/tutorial/google.md)
  - The [OIDC documentation](`AshAuthentication.Strategy.Oidc`)
  """

  alias AshAuthentication.Strategy.{Custom, Oidc}

  use Custom, entity: Dsl.dsl()

  defdelegate transform(strategy, dsl_state), to: Oidc
  defdelegate verify(strategy, dsl_state), to: Oidc
end
