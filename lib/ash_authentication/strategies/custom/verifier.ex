# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Custom.Verifier do
  @moduledoc """
  Verifier used by custom strategies.

  It delegates verification passes to the individual strategies.
  """

  use Spark.Dsl.Verifier

  alias AshAuthentication.Info

  @doc false
  @impl true
  @spec verify(map) ::
          :ok
          | {:error, term}
          | {:warn, String.t() | list(String.t())}
  def verify(dsl_state) do
    dsl_state
    |> Info.authentication_strategies()
    |> Stream.concat(Info.authentication_add_ons(dsl_state))
    |> Enum.reduce_while(:ok, fn
      strategy, :ok ->
        strategy_module = strategy_module(strategy)

        strategy
        |> strategy_module.verify(dsl_state)
        |> case do
          :ok -> {:cont, :ok}
          {:error, reason} -> {:halt, {:error, reason}}
        end
    end)
  end

  # This is needed by some strategies which re-use another strategy's entity (ie everything based on oauth2).
  defp strategy_module(strategy) when is_nil(strategy.strategy_module), do: strategy.__struct__

  defp strategy_module(strategy) when is_atom(strategy.strategy_module),
    do: strategy.strategy_module

  defp strategy_module(strategy), do: strategy.__struct__
end
