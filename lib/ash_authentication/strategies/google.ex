defmodule AshAuthentication.Strategy.Google do
  alias __MODULE__.Dsl

  @moduledoc """
  Strategy for authenticating using [Google](https://google.com)

  This strategy builds on-top of `AshAuthentication.Strategy.OAuth2` and
  [`assent`](https://hex.pm/packages/assent).

  In order to use Google you need to provide the following minimum configuration:

    - `client_id`
    - `redirect_uri`
    - `client_secret`
    - `site`

  ## More documentation:
  - The [Google OAuth 2.0 Overview](https://developers.google.com/identity/protocols/oauth2).
  - The [Google Tutorial](/documentation/tutorial/google.md)
  - The [OAuth2 documentation](`AshAuthentication.Strategy.OAuth2`)
  """

  alias AshAuthentication.Strategy.{Custom, OAuth2}

  use Custom, entity: Dsl.dsl()

  defdelegate transform(strategy, dsl_state), to: OAuth2
  defdelegate verify(strategy, dsl_state), to: OAuth2
end
