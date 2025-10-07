# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Slack do
  alias __MODULE__.{Dsl, Verifier}

  @moduledoc """
  Strategy for authenticating using [Slack](https://slack.com)

  This strategy builds on-top of `AshAuthentication.Strategy.Oidc` and
  [`assent`](https://hex.pm/packages/assent).

  In order to use Slack you need to provide the following minimum configuration:

    - `client_id`
    - `redirect_uri`
    - `client_secret`

  ## More documentation:
  - The [Slack Tutorial](/documentation/tutorial/slack.md).
  - The [OIDC documentation](`AshAuthentication.Strategy.Oidc`)
  """

  alias AshAuthentication.Strategy.{Custom, Oidc}

  use Custom, entity: Dsl.dsl()

  defdelegate transform(strategy, dsl_state), to: Oidc
  defdelegate verify(strategy, dsl_state), to: Verifier
end
