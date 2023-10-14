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

  See the [Google OAuth 2.0 Overview](https://developers.google.com/identity/protocols/oauth2)
  for Google setup details.

  ## DSL Documentation

  #{Spark.Dsl.Extension.doc_entity(Dsl.dsl())}
  """

  alias AshAuthentication.Strategy.{Custom, OAuth2}

  use Custom, entity: Dsl.dsl()

  defdelegate transform(strategy, dsl_state), to: OAuth2
  defdelegate verify(strategy, dsl_state), to: OAuth2
end
