defmodule AshAuthentication.Strategy.Auth0 do
  alias __MODULE__.Dsl

  @moduledoc """
  Strategy for authenticating using [Auth0](https://auth0.com).

  This strategy builds on-top of `AshAuthentication.Strategy.OAuth2` and
  [`assent`](https://hex.pm/packages/assent).

  In order to use Auth0 you need to provide the following minimum configuration:

    - `client_id`
    - `redirect_uri`
    - `client_secret`
    - `site`

  ## More documentation:
  - The [Auth0 Tutorial](/documentation/tutorial/auth0.md).
  - The [OAuth2 documentation](`AshAuthentication.Strategy.OAuth2`)
  """

  alias AshAuthentication.Strategy.{Custom, OAuth2}

  use Custom, entity: Dsl.dsl()

  defdelegate transform(strategy, dsl_state), to: OAuth2
  defdelegate verify(strategy, dsl_state), to: OAuth2
end
