# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.ApiKey.Transformer do
  @moduledoc """
  DSL transformer for API keys.
  """

  alias AshAuthentication.Strategy.ApiKey
  import AshAuthentication.Strategy.Custom.Helpers

  @doc false
  @spec transform(ApiKey.t(), dsl_state) :: {:ok, ApiKey.t() | dsl_state} | {:error, any}
        when dsl_state: map
  def transform(strategy, dsl_state) do
    with strategy <- maybe_set_sign_in_action_name(strategy) do
      dsl_state =
        dsl_state
        |> then(
          &register_strategy_actions(
            [strategy.sign_in_action_name],
            &1,
            strategy
          )
        )
        |> put_strategy(strategy)

      {:ok, dsl_state}
    end
  end

  # sobelow_skip ["DOS.StringToAtom"]
  defp maybe_set_sign_in_action_name(strategy) when is_nil(strategy.sign_in_action_name),
    do: %{strategy | sign_in_action_name: String.to_atom("sign_in_with_#{strategy.name}")}

  defp maybe_set_sign_in_action_name(strategy), do: strategy
end
