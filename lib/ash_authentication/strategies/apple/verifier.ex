# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Apple.Verifier do
  @moduledoc """
  DSL verifier for Apple strategy.
  """

  alias AshAuthentication.Strategy.OAuth2
  alias Spark.Error.DslError
  import AshAuthentication.Validations

  @doc false
  @spec verify(OAuth2.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl_state) do
    with :ok <- validate_secret(strategy, :client_id),
         :ok <- validate_secret(strategy, :team_id),
         :ok <- validate_secret(strategy, :private_key_id),
         :ok <- validate_secret(strategy, :redirect_uri),
         :ok <- validate_private_key(strategy) do
      oauth2_strategy_warnings(strategy, dsl_state)
    end
  end

  defp validate_private_key(%{private_key: nil} = strategy),
    do: validate_secret(strategy, :private_key_path)

  defp validate_private_key(%{private_key_path: nil} = strategy),
    do: validate_secret(strategy, :private_key)

  defp validate_private_key(strategy) do
    {:error,
     DslError.exception(
       path: [:authentication, :strategies, strategy.name],
       message: "Either `private_key_path` or `private_key` must be configured, not both.",
       module: strategy.resource
     )}
  end
end
