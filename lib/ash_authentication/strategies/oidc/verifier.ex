# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Oidc.Verifier do
  @moduledoc """
  DSL verifier for OpenID Connect strategy.
  """

  alias AshAuthentication.Strategy.OAuth2
  import AshAuthentication.Validations

  @doc false
  @spec verify(OAuth2.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl_state) do
    with :ok <- validate_secret(strategy, :client_id),
         :ok <- validate_secret(strategy, :client_secret, [nil]),
         :ok <- validate_secret(strategy, :base_url),
         :ok <- validate_secret(strategy, :nonce, [true, false]),
         :ok <- OAuth2.Verifier.prevent_hijacking(dsl_state, strategy),
         :ok <- validate_private_key(strategy) do
      oauth2_strategy_warnings(strategy, dsl_state)
    end
  end

  defp validate_private_key(%{auth_method: :private_key_jwt} = strategy),
    do: validate_exclusive_secret(strategy, [:private_key, :private_key_path])

  defp validate_private_key(_strategy), do: :ok
end
