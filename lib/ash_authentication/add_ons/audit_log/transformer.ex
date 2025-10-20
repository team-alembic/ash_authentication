# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog.Transformer do
  @moduledoc false
  alias Spark.Dsl.Transformer

  @doc false
  def transform(strategy, dsl) do
    with {:ok, strategy, dsl} <- prefill_included(strategy, dsl),
         {:ok, logged_actions} <- find_logged_actions(strategy, dsl),
         {:ok, dsl} <- persist_logged_actions(strategy, dsl, logged_actions),
         {:ok, dsl} <- persist_logged_fields(strategy, dsl, logged_actions),
         {:ok, dsl} <- add_global_change(strategy, dsl) do
      add_global_preparation(strategy, dsl)
    end
  end

  defp prefill_included(strategy, dsl) do
    with {:ok, strategy} <- prefill_included_strategies(strategy, dsl),
         {:ok, strategy} <- prefill_included_actions(strategy, dsl) do
      {:ok, strategy,
       Transformer.replace_entity(
         dsl,
         [:authentication, :add_ons],
         strategy,
         &(&1.name == strategy.name)
       )}
    end
  end

  defp prefill_included_strategies(strategy, dsl) when strategy.include_strategies == [:*] do
    strategy_names =
      dsl
      |> AshAuthentication.Info.list_strategies()
      |> Enum.map(& &1.name)

    {:ok, %{strategy | include_strategies: strategy_names}}
  end

  defp prefill_included_strategies(strategy, _dsl), do: {:ok, strategy}

  defp prefill_included_actions(strategy, dsl) when strategy.include_actions == [:*] do
    action_names =
      dsl
      |> Ash.Resource.Info.actions()
      |> Enum.map(& &1.name)

    {:ok, %{strategy | include_actions: action_names}}
  end

  defp prefill_included_actions(strategy, _dsl), do: {:ok, strategy}

  defp find_logged_actions(strategy, dsl) do
    logged_actions =
      strategy.include_actions
      |> Stream.map(fn action_name ->
        # For actions that belong to a strategy, use the strategy name
        # For actions that don't belong to any strategy, use :audit_log as the strategy
        case AshAuthentication.Info.strategy_for_action(dsl, action_name) do
          {:ok, action_strategy} -> {action_name, action_strategy.name}
          :error -> {action_name, :audit_log}
        end
      end)
      |> Stream.reject(&(elem(&1, 0) in strategy.exclude_actions))
      |> Stream.reject(&(elem(&1, 1) in strategy.exclude_strategies))
      |> Enum.to_list()

    {:ok, logged_actions}
  end

  defp persist_logged_actions(strategy, dsl, logged_actions) do
    dsl =
      dsl
      |> Transformer.persist({:audit_log, strategy.name, :actions}, logged_actions)

    {:ok, dsl}
  end

  defp persist_logged_fields(strategy, dsl, logged_actions) do
    attributes = Ash.Resource.Info.attributes(dsl)
    actions = Ash.Resource.Info.actions(dsl)

    # Extract just the action names from the tuples
    logged_action_names = Enum.map(logged_actions, &elem(&1, 0))

    actions
    |> Enum.filter(&(&1.name in logged_action_names))
    |> Enum.reduce({:ok, dsl}, fn action, {:ok, dsl} ->
      argument_names =
        action.arguments
        |> Enum.filter(&include_in_fields?(&1, strategy))
        |> Enum.map(& &1.name)

      attribute_names =
        attributes
        |> Enum.filter(&include_in_fields?(&1, strategy))
        |> Enum.map(& &1.name)
        |> Enum.reject(&(&1 in argument_names))

      dsl =
        dsl
        |> Transformer.persist(
          {:audit_log, strategy.name, action.name, :arguments},
          argument_names
        )
        |> Transformer.persist(
          {:audit_log, strategy.name, action.name, :attributes},
          attribute_names
        )

      {:ok, dsl}
    end)
  end

  defp include_in_fields?(arg_or_attr, strategy) do
    cond do
      arg_or_attr.public? && !arg_or_attr.sensitive? -> true
      arg_or_attr.name in strategy.include_fields -> true
      true -> false
    end
  end

  defp add_global_change(strategy, dsl) do
    with {:ok, change} <-
           Transformer.build_entity(Ash.Resource.Dsl, [:changes], :change,
             change: {AshAuthentication.AddOn.AuditLog.Auditor.Change, strategy: strategy.name},
             on: [:create, :update, :destroy]
           ) do
      {:ok, Transformer.add_entity(dsl, [:changes], change)}
    end
  end

  defp add_global_preparation(strategy, dsl) do
    with {:ok, prep} <-
           Transformer.build_entity(Ash.Resource.Dsl, [:preparations], :prepare,
             preparation:
               {AshAuthentication.AddOn.AuditLog.Auditor.Preparation, strategy: strategy.name},
             on: [:read, :action]
           ) do
      {:ok, Transformer.add_entity(dsl, [:preparations], prep)}
    end
  end
end
