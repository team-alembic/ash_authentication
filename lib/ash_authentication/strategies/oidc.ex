defmodule AshAuthentication.Strategy.Oidc do
  alias __MODULE__.Dsl

  @moduledoc """
  Strategy for authentication using an [OpenID
  Connect](https://openid.net/connect/) compatible server as the source of
  truth.

  This strategy builds on-top of `AshAuthentication.Strategy.OAuth2` and
  [`assent`](https://hex.pm/packages/assent).

  In order to use OIDC you need to provide the following minimum configuration:

  - `client_id` - The client id, required
  - `site` - The OIDC issuer, required
  - `openid_configuration_uri` - The URI for OpenID Provider, optional, defaults
    to `/.well-known/openid-configuration`
  - `client_authentication_method` - The Client Authentication method to use,
    optional, defaults to `client_secret_basic`
  - `client_secret` - The client secret, required if
    `:client_authentication_method` is `:client_secret_basic`,
    `:client_secret_post`, or `:client_secret_jwt`
  - `openid_configuration` - The OpenID configuration, optional, the
    configuration will be fetched from `:openid_configuration_uri` if this is
    not defined
  - `id_token_signed_response_alg` - The `id_token_signed_response_alg`
    parameter sent by the Client during Registration, defaults to `RS256`
  - `id_token_ttl_seconds` - The number of seconds from `iat` that an ID Token
    will be considered valid, optional, defaults to nil
  - `nonce` - The nonce to use for authorization request, optional, MUST be
    session based and unguessable.


  ## Nonce
  `nonce` can be set in the provider config. The `nonce` will be returned in the
  `session_params` along with `state`. You can use this to store the value in
  the current session e.g. a httpOnly session cookie.

  A random value generator can look like this:

  ```elixir
  16
  |> :crypto.strong_rand_bytes()
  |> Base.encode64(padding: false)
  ```

  AshAuthentication will dynamically generate one for the session if `nonce` is
  set to `true`.

  ## More documentation:
  - The [OAuth2 documentation](`AshAuthentication.Strategy.OAuth2`)
  """

  alias AshAuthentication.Strategy.{Custom, Oidc}
  use Custom, entity: Dsl.dsl()

  defdelegate transform(strategy, dsl_state), to: Oidc.Transformer
  defdelegate verify(strategy, dsl_state), to: Oidc.Verifier
end
