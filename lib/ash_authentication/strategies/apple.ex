defmodule AshAuthentication.Strategy.Apple do
  alias __MODULE__.{Dsl, Verifier}

  @moduledoc """
  Strategy for authenticating using [Apple Sign In](https://developer.apple.com/sign-in-with-apple/)

  This strategy builds on-top of `AshAuthentication.Strategy.Oidc` and
  [`assent`](https://hex.pm/packages/assent).

  In order to use Apple Sign In you need to provide the following minimum configuration:

    - `client_id`
    - `team_id`
    - `private_key_id`
    - `private_key_path`
    - `redirect_uri`

  ## More documentation:
  - The [Apple Sign In Documentation](https://developer.apple.com/documentation/sign_in_with_apple).
  - The [OIDC documentation](`AshAuthentication.Strategy.Oidc`)
  """

  alias AshAuthentication.Strategy.{Custom, Oidc}

  use Custom, entity: Dsl.dsl()

  defdelegate transform(strategy, dsl_state), to: Oidc
  defdelegate verify(strategy, dsl_state), to: Verifier
end
