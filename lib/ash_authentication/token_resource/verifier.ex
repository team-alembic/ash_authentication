# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.TokenResource.Verifier do
  @moduledoc """
  The token resource verifier.
  """

  use Spark.Dsl.Verifier
  require Ash.Expr
  require Logger
  alias Spark.{Dsl.Verifier, Error.DslError}
  import AshAuthentication.Utils
  import AshAuthentication.Validations.Action

  @doc false
  @impl true
  @spec verify(map) :: :ok | {:error, term}
  def verify(dsl_state) do
    with :ok <- validate_domain_presence(dsl_state) do
      maybe_validate_is_revoked_action_arguments(dsl_state)
    end
  end

  defp maybe_validate_is_revoked_action_arguments(dsl_state) do
    case Verifier.get_option(dsl_state, [:token, :revocation], :is_revoked_action_name, :revoked?) do
      nil ->
        :ok

      action_name ->
        case validate_action_exists(dsl_state, action_name) do
          {:ok, action} -> validate_is_revoked_action(dsl_state, action)
          {:error, _} -> :ok
        end
    end
  end

  defp validate_is_revoked_action(dsl_state, action) do
    if action.type == :action do
      with :ok <- validate_action_argument_option(action, :jti, :allow_nil?, [true]),
           :ok <- validate_action_argument_option(action, :token, :allow_nil?, [true]),
           :ok <- validate_action_option(action, :returns, [:boolean, Ash.Type.Boolean]) do
        :ok
      else
        {:error, _} ->
          Logger.warning("""
          Warning while compiling #{inspect(Verifier.get_persisted(dsl_state, :module))}:

          The `:jti` and `:token` options to the `#{inspect(action.name)}` action must allow nil values and it must return a `:boolean`.

          This was an error in our igniter installer previous to version 4.4.9, which allowed revoked tokens to be reused.

          To fix this, run the following command in your shell:

              mix ash_authentication.upgrade 4.4.8 4.4.9

          Or:

            - remove `allow_nil?: false` from these action arguments, and
            - ensure that the action returns `:boolean`.

            like so:

              action :revoked?, :boolean do
                description "Returns true if a revocation token is found for the provided token"
                argument :token, :string, sensitive?: true
                argument :jti, :string, sensitive?: true

                run AshAuthentication.TokenResource.IsRevoked
              end
          """)

          :ok
      end
    else
      :ok
    end
  end

  defp validate_domain_presence(dsl_state) do
    with domain when not is_nil(domain) <- Verifier.get_option(dsl_state, [:token], :domain),
         :ok <- assert_is_module(domain),
         true <- function_exported?(domain, :spark_is, 0),
         Ash.Domain <- domain.spark_is() do
      :ok
    else
      nil ->
        {:error,
         DslError.exception(
           path: [:token, :domain],
           message: "A domain module must be present"
         )}

      _ ->
        {:error,
         DslError.exception(
           path: [:token, :domain],
           message: "Module is not an `Ash.Domain`."
         )}
    end
  end
end
