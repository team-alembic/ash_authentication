# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

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
  # Strategy transformers add auto-generated `get_by_<identity_field>` read
  # actions (password, magic_link). Ash's GetByReadActions transformer is what
  # turns their `get_by:` option into an actual filter — so it must run *after*
  # the strategy transformers have added those actions, otherwise the actions
  # stay unfiltered and `Ash.read_one` raises MultipleResults once more than
  # one row exists.
  def before?(Ash.Resource.Transformers.GetByReadActions), do: true
  # Strategy transformers also add `has_many` relationships (webauthn's
  # credentials, for one) without naming a `destination_attribute`, so that
  # Ash derives it from this resource's name rather than the strategy having
  # to guess a foreign key on a resource it can't introspect yet. That
  # derivation is `HasDestinationField`'s job, so it has to run after the
  # relationships exist — otherwise they keep a `nil` destination attribute.
  def before?(Ash.Resource.Transformers.HasDestinationField), do: true
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
    strategy_module = strategy_module(strategy)

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

  defp do_transform(strategy, dsl_state, :add_on) do
    strategy = %{strategy | resource: Transformer.get_persisted(dsl_state, :module)}
    dsl_state = put_add_on(dsl_state, strategy)
    entity_module = strategy.__struct__
    strategy_module = strategy_module(strategy)

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

  # This is needed by some strategies which re-use another strategy's entity (ie everything based on oauth2).
  defp strategy_module(strategy) when is_nil(strategy.strategy_module), do: strategy.__struct__

  defp strategy_module(strategy) when is_atom(strategy.strategy_module),
    do: strategy.strategy_module

  defp strategy_module(strategy), do: strategy.__struct__
end
