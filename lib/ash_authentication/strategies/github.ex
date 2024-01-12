defmodule AshAuthentication.Strategy.Github do
  alias __MODULE__.Dsl

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

  use Custom, entity: Dsl.dsl()

  defdelegate transform(strategy, dsl_state), to: OAuth2
  defdelegate verify(strategy, dsl_state), to: OAuth2
end
