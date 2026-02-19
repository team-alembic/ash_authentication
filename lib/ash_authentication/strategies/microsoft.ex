# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Microsoft do
  alias __MODULE__.Dsl

  @moduledoc """
  Strategy for authenticating using [Microsoft](https://microsoft.com)

  This strategy builds on-top of `AshAuthentication.Strategy.Oidc` and
  [`assent`](https://hex.pm/packages/assent).

  It uses Microsoft's OpenID Connect discovery endpoint to automatically
  retrieve token, authorization, and user info URLs. User identity claims
  (email, name, etc.) are extracted from the ID token returned during the
  authorization code flow.

  In order to use Microsoft you need to provide the following minimum configuration:

    - `client_id`
    - `redirect_uri`
    - `client_secret`

  By default the strategy uses the `common` tenant endpoint, which allows any
  Microsoft account. To restrict sign-in to a specific Azure tenant, override
  `base_url`:

      base_url "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0"

  ## More documentation:
  - The [Microsoft OpenID Connect Overview](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc).
  - The [Microsoft Tutorial](/documentation/tutorials/microsoft.md)
  - The [OIDC documentation](`AshAuthentication.Strategy.Oidc`)
  """

  alias AshAuthentication.Strategy.{Custom, Oidc}

  use Custom, entity: Dsl.dsl()

  defdelegate transform(strategy, dsl_state), to: Oidc
  defdelegate verify(strategy, dsl_state), to: Oidc
end
