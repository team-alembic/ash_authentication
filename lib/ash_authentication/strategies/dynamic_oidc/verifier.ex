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
    - `idp_initiated_login?` is not enabled — it cannot be supported here, so
      setting it is rejected at compile time with an explanatory error.
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
         :ok <- validate_connection_resource(strategy),
         :ok <- reject_idp_initiated_login(strategy),
         :ok <- OAuth2.Verifier.prevent_hijacking(dsl_state, strategy),
         :ok <- OAuth2.Verifier.validate_confirmation_for_untrusted_match(dsl_state, strategy) do
      oauth2_strategy_warnings(strategy, dsl_state)
    end
  end

  # `idp_initiated_login?` restarts the request phase to obtain a verifiable
  # `state`. For a dynamic strategy the request phase resolves its provider
  # config from a `connection_id` in its path, but an IdP-initiated callback
  # carries no `connection_id` to restart with — so the restart cannot build an
  # authorize URL. Selecting a connection from an IdP-initiated launch is a
  # provider-specific concern (a launch's tenant claim → connection lookup) and
  # is out of scope for this flag; fail loudly rather than accept a setting that
  # would silently never fire.
  defp reject_idp_initiated_login(%{idp_initiated_login?: true} = strategy) do
    {:error,
     DslError.exception(
       path: [:authentication, :strategies, strategy.name, :idp_initiated_login?],
       message:
         "`idp_initiated_login?` is not supported on `dynamic_oidc`: an IdP-initiated " <>
           "callback carries no `connection_id`, so the request-phase restart cannot " <>
           "resolve the connection's provider config. Use a statically-configured " <>
           "OAuth2/OIDC strategy for IdP-initiated login."
     )}
  end

  defp reject_idp_initiated_login(_strategy), do: :ok

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
