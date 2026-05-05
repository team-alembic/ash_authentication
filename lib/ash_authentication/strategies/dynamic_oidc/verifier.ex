# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.DynamicOidc.Verifier do
  @moduledoc """
  DSL verifier for `dynamic_oidc` strategies.

  Confirms that:
    - The configured `connection_resource` has the
      `AshAuthentication.OidcConnection` extension.
    - The standard `redirect_uri` secret is present.
    - The OAuth2-derived `prevent_hijacking?` guard fires when paired with
      a password strategy without a confirmation add-on.
  """

  alias AshAuthentication.Strategy.{DynamicOidc, OAuth2}
  alias Spark.Error.DslError
  import AshAuthentication.Validations

  @doc false
  @spec verify(DynamicOidc.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl_state) do
    with :ok <- validate_secret(strategy, :redirect_uri),
         :ok <- validate_connection_resource(strategy) do
      OAuth2.Verifier.prevent_hijacking(dsl_state, strategy)
    end
  end

  defp validate_connection_resource(strategy) do
    connection_resource = strategy.connection_resource

    if connection_resource &&
         AshAuthentication.OidcConnection in Spark.extensions(connection_resource) do
      :ok
    else
      {:error,
       DslError.exception(
         path: [:authentication, :strategies, strategy.name, :connection_resource],
         message:
           "`#{inspect(connection_resource)}` must use the `AshAuthentication.OidcConnection` extension."
       )}
    end
  end
end
