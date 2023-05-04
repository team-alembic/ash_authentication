defmodule AshAuthentication.Strategy.Custom.Transformer do
  @moduledoc """
  Transformer used by custom strategies.

  It delegates transformation passes to the individual strategies.
  """

  use Spark.Dsl.Transformer

  alias AshAuthentication.{Info, Strategy}
  alias Spark.{Dsl.Transformer, Error.DslError}
  import AshAuthentication.Strategy.Custom.Helpers

  @doc false
  @impl true
  @spec after?(module) :: boolean
  def after?(AshAuthentication.Transformer), do: true
  def after?(_), do: false

  @doc false
  @impl true
  @spec before?(module) :: boolean
  def before?(Resource.Transformers.DefaultAccept), do: true
  def before?(_), do: false

  @doc false
  @impl true
  @spec transform(map) ::
          :ok
          | {:ok, map()}
          | {:error, term()}
          | {:warn, map(), String.t() | [String.t()]}
          | :halt
  def transform(dsl_state) do
    with {:ok, dsl_state} <- do_strategy_transforms(dsl_state) do
      do_add_on_transforms(dsl_state)
    end
  end

  defp do_strategy_transforms(dsl_state) do
    dsl_state
    |> Info.authentication_strategies()
    |> Enum.reduce_while({:ok, dsl_state}, fn strategy, {:ok, dsl_state} ->
      case do_transform(strategy, dsl_state, :strategy) do
        {:ok, dsl_state} -> {:cont, {:ok, dsl_state}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp do_add_on_transforms(dsl_state) do
    dsl_state
    |> Info.authentication_add_ons()
    |> Enum.reduce_while({:ok, dsl_state}, fn strategy, {:ok, dsl_state} ->
      case do_transform(strategy, dsl_state, :add_on) do
        {:ok, dsl_state} -> {:cont, {:ok, dsl_state}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp do_transform(strategy, _, _) when not is_map_key(strategy, :strategy_module) do
    name = Strategy.name(strategy)

    {:error,
     DslError.exception(
       path: [:authentication, name],
       message:
         "The struct defined by `#{inspect(strategy.__struct__)}` must contain a `strategy_module` field."
     )}
  end

  defp do_transform(strategy, _, _) when not is_map_key(strategy, :resource) do
    name = Strategy.name(strategy)

    {:error,
     DslError.exception(
       path: [:authentication, name],
       message:
         "The struct defined by `#{inspect(strategy.__struct__)}` must contain a `resource` field."
     )}
  end

  defp do_transform(strategy, dsl_state, :strategy) do
    strategy = %{strategy | resource: Transformer.get_persisted(dsl_state, :module)}
    dsl_state = put_strategy(dsl_state, strategy)
    entity_module = strategy.__struct__

    strategy
    |> strategy.strategy_module.transform(dsl_state)
    |> case do
      {:ok, strategy} when is_struct(strategy, entity_module) ->
        {:ok, put_strategy(dsl_state, strategy)}

      {:ok, dsl_state} when is_map(dsl_state) ->
        {:ok, dsl_state}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_transform(strategy, dsl_state, :add_on) do
    strategy = %{strategy | resource: Transformer.get_persisted(dsl_state, :module)}
    dsl_state = put_add_on(dsl_state, strategy)
    entity_module = strategy.__struct__

    strategy
    |> strategy.strategy_module.transform(dsl_state)
    |> case do
      {:ok, strategy} when is_struct(strategy, entity_module) ->
        {:ok, put_add_on(dsl_state, strategy)}

      {:ok, dsl_state} when is_map(dsl_state) ->
        {:ok, dsl_state}

      {:error, reason} ->
        {:error, reason}
    end
  end
end
