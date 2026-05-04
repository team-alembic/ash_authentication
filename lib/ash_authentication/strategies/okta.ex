# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Okta do
  alias __MODULE__.Dsl

  @moduledoc """
  Strategy for authenticating using [Okta](https://okta.com).

  This strategy builds on-top of `AshAuthentication.Strategy.Oidc` and
  [`assent`](https://hex.pm/packages/assent), and uses Okta's OpenID Connect
  discovery endpoint to retrieve token, authorization, and user info URLs.

  In order to use Okta you need to provide the following minimum configuration:

    - `client_id`
    - `client_secret`
    - `redirect_uri`
    - `base_url` - your Okta authorization server, typically
      `https://YOUR_OKTA_DOMAIN/oauth2/default` (the built-in `default`
      Custom Authorization Server).

  > #### Choosing a `base_url` {: .info}
  >
  > Okta exposes two kinds of authorization servers:
  >
  > - **Custom Authorization Server** (recommended) — issuer
  >   `https://YOUR_OKTA_DOMAIN/oauth2/{authServerId}`. Every Okta org ships
  >   with one named `default`.
  > - **Org Authorization Server** — issuer `https://YOUR_OKTA_DOMAIN`. Only
  >   suitable for a small number of Okta-internal use cases.
  >
  > If you're not sure, use the `default` Custom Authorization Server.

  ## More documentation:
  - The [Okta Tutorial](/documentation/tutorials/okta.md) — covers groups
    claims, step-up / MFA via `acr_values`, and Org vs Custom server choice
    in depth.
  - The [Okta OpenID Connect Overview](https://developer.okta.com/docs/concepts/oauth-openid/).
  - The [OIDC documentation](`AshAuthentication.Strategy.Oidc`).
  """

  alias AshAuthentication.Strategy.{Custom, Oidc}

  use Custom, entity: Dsl.dsl()

  defdelegate transform(strategy, dsl_state), to: Oidc
  defdelegate verify(strategy, dsl_state), to: Oidc
end
