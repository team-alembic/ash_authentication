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
  Microsoft account (personal, work, or school). Multi-tenant issuer validation
  is handled by Assent using tenant-specific discovery and ID token verification.

  To restrict sign-in to a specific Azure tenant, use its directory UUID in
  `base_url`. Verified tenant domains are not supported:

      base_url "https://login.microsoftonline.com/YOUR_TENANT_ID/v2.0"

  ## More documentation:
  - The [Microsoft OpenID Connect Overview](https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc).
  - The [Microsoft Tutorial](/documentation/tutorials/microsoft.md)
  - The [OIDC documentation](`AshAuthentication.Strategy.Oidc`)
  """

  alias AshAuthentication.Strategy.{Custom, Microsoft.AzureADMultitenant, Oidc}
  alias Spark.Error.DslError

  use Custom, entity: Dsl.dsl()

  defdelegate transform(strategy, dsl_state), to: Oidc

  @doc false
  def verify(strategy, dsl_state) do
    with :ok <- verify_base_url(strategy), do: Oidc.verify(strategy, dsl_state)
  end

  # A literal base_url can be checked at compile time. Secrets are checked when
  # the request and callback phases resolve them.
  defp verify_base_url(%{base_url: base_url} = strategy) when is_binary(base_url) do
    case AzureADMultitenant.canonical_base_url(base_url) do
      {:ok, _base_url} ->
        :ok

      {:error, error} ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, strategy.name, :base_url],
           message: Exception.message(error),
           module: strategy.resource
         )}
    end
  end

  defp verify_base_url(_strategy), do: :ok
end
