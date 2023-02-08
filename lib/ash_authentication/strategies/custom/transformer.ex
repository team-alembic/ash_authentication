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
    strategy_to_target =
      :code.all_available()
      |> Stream.map(&elem(&1, 0))
      |> Stream.map(&to_string/1)
      |> Stream.filter(&String.starts_with?(&1, "Elixir.AshAuthentication"))
      |> Stream.map(&Module.concat([&1]))
      |> Stream.concat(Transformer.get_persisted(dsl_state, :extensions, []))
      |> Stream.filter(&Spark.implements_behaviour?(&1, Strategy.Custom))
      |> Stream.flat_map(fn strategy ->
        strategy.dsl_patches()
        |> Stream.map(&{&1.entity.target, strategy})
      end)
      |> Map.new()

    dsl_state =
      Transformer.persist(dsl_state, :ash_authentication_strategy_to_target, strategy_to_target)

    with {:ok, dsl_state} <- do_strategy_transforms(dsl_state, strategy_to_target) do
      do_add_on_transforms(dsl_state, strategy_to_target)
    end
  end

  defp do_strategy_transforms(dsl_state, strategy_to_target) do
    dsl_state
    |> Info.authentication_strategies()
    |> Enum.reduce_while({:ok, dsl_state}, fn strategy, {:ok, dsl_state} ->
      strategy_module = Map.fetch!(strategy_to_target, strategy.__struct__)

      case do_transform(strategy_module, strategy, dsl_state, :strategy) do
        {:ok, dsl_state} -> {:cont, {:ok, dsl_state}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp do_add_on_transforms(dsl_state, strategy_to_target) do
    dsl_state
    |> Info.authentication_add_ons()
    |> Enum.reduce_while({:ok, dsl_state}, fn strategy, {:ok, dsl_state} ->
      strategy_module = Map.fetch!(strategy_to_target, strategy.__struct__)

      case do_transform(strategy_module, strategy, dsl_state, :add_on) do
        {:ok, dsl_state} -> {:cont, {:ok, dsl_state}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp do_transform(strategy_module, strategy, dsl_state, :strategy)
       when is_map_key(strategy, :resource) do
    strategy = %{strategy | resource: Transformer.get_persisted(dsl_state, :module)}
    dsl_state = put_strategy(dsl_state, strategy)
    entity_module = strategy.__struct__

    strategy
    |> strategy_module.transform(dsl_state)
    |> case do
      {:ok, strategy} when is_struct(strategy, entity_module) ->
        {:ok, put_strategy(dsl_state, strategy)}

      {:ok, dsl_state} when is_map(dsl_state) ->
        {:ok, dsl_state}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_transform(strategy_module, strategy, dsl_state, :add_on)
       when is_map_key(strategy, :resource) do
    strategy = %{strategy | resource: Transformer.get_persisted(dsl_state, :module)}
    dsl_state = put_add_on(dsl_state, strategy)
    entity_module = strategy.__struct__

    strategy
    |> strategy_module.transform(dsl_state)
    |> case do
      {:ok, strategy} when is_struct(strategy, entity_module) ->
        {:ok, put_add_on(dsl_state, strategy)}

      {:ok, dsl_state} when is_map(dsl_state) ->
        {:ok, dsl_state}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp do_transform(_strategy_module, strategy, _, _) do
    name = Strategy.name(strategy)

    {:error,
     DslError.exception(
       path: [:authentication, name],
       message:
         "The struct defined by `#{inspect(strategy.__struct__)}` must contain a `resource` field."
     )}
  end
end
