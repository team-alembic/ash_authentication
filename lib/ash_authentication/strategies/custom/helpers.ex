defmodule AshAuthentication.Strategy.Custom.Helpers do
  @moduledoc """
  Helpers for use within custom strategies.
  """

  alias AshAuthentication.{Strategy, Strategy.Custom}
  alias Spark.Dsl.Transformer

  @doc """
  If there's any chance that an implementor may try and use actions genrated by
  your strategy programatically then you should register your actions with Ash
  Authentication so that it can find the appropriate strategy when needed.

  The strategy can be retrieved again by calling
  `AshAuthentication.Info.strategy_for_action/2`.

  This helper should only be used within transformers.
  """
  @spec register_strategy_actions(action_or_actions, dsl_state, Custom.strategy()) :: dsl_state
        when dsl_state: map, action_or_actions: atom | [atom]
  def register_strategy_actions(action, dsl_state, strategy) when is_atom(action),
    do: register_strategy_actions([action], dsl_state, strategy)

  def register_strategy_actions(actions, dsl_state, strategy),
    do:
      Enum.reduce(
        actions,
        dsl_state,
        &Transformer.persist(&2, {:authentication_action, &1}, strategy)
      )

  @doc """
  Update the strategy in the DSL state by name.

  This helper should only be used within transformers.
  """
  @spec put_strategy(dsl_state, Custom.strategy()) :: dsl_state when dsl_state: map
  def put_strategy(dsl_state, strategy),
    do: put_entity(dsl_state, strategy, ~w[authentication strategies]a)

  @doc """
  Update the add-on in the DSL state by name.

  This helper should only be used within transformers.
  """
  @spec put_add_on(dsl_state, Custom.strategy()) :: dsl_state when dsl_state: map
  def put_add_on(dsl_state, strategy),
    do: put_entity(dsl_state, strategy, ~w[authentication add_ons]a)

  defp put_entity(dsl_state, strategy, path) do
    name = Strategy.name(strategy)

    dsl_state
    |> Transformer.remove_entity(path, &(Strategy.name(&1) == name))
    |> Transformer.add_entity(path, strategy)
  end
end
