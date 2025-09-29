defmodule AshAuthentication.AddOn.AuditLog.Transformer do
  @moduledoc false
  alias Spark.Dsl.Transformer

  @doc false
  def transform(strategy, dsl) do
    with {:ok, logged_actions} <- find_logged_actions(strategy, dsl),
         {:ok, dsl} <- persist_logged_actions(strategy, dsl, logged_actions),
         {:ok, dsl} <- persist_logged_fields(strategy, dsl, logged_actions),
         {:ok, dsl} <- add_global_change(strategy, dsl) do
      add_global_preparation(strategy, dsl)
    end
  end

  defp find_logged_actions(strategy, dsl) do
    logged_actions =
      dsl
      |> Ash.Resource.Info.actions()
      |> Stream.map(& &1.name)
      |> Stream.reject(&(&1 in strategy.exclude_actions))
      |> Enum.reject(fn action_name ->
        case AshAuthentication.Info.strategy_for_action(dsl, action_name) do
          {:ok, target_strategy} ->
            target_strategy in strategy.exclude_strategies ||
              target_strategy.provider == :audit_log

          :error ->
            true
        end
      end)

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

    actions
    |> Enum.filter(&(&1.name in logged_actions))
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
