defmodule AshAuthentication.Info do
  @moduledoc """
  Generated configuration functions based on a resource's DSL configuration.
  """

  use Spark.InfoGenerator,
    extension: AshAuthentication,
    sections: [:authentication]

  alias AshAuthentication.Strategy
  alias Spark.Dsl.Extension

  @type dsl_or_resource :: module | map

  @doc """
  Retrieve a named strategy from a resource.
  """
  @spec strategy(dsl_or_resource | module, atom) :: {:ok, strategy} | :error
        when strategy: struct
  def strategy(dsl_or_resource, name) do
    dsl_or_resource
    |> authentication_strategies()
    |> Stream.concat(authentication_add_ons(dsl_or_resource))
    |> Enum.find_value(:error, fn strategy ->
      if Strategy.name(strategy) == name, do: {:ok, strategy}
    end)
  end

  @doc """
  Retrieve a named strategy from a resource (raising version).
  """
  @spec strategy!(dsl_or_resource | module, atom) :: strategy | no_return
        when strategy: struct
  def strategy!(dsl_or_resource, name) do
    case strategy(dsl_or_resource, name) do
      {:ok, strategy} ->
        strategy

      :error ->
        raise "No strategy named `#{inspect(name)}` found on resource `#{inspect(dsl_or_resource)}`"
    end
  end

  @doc """
  Given an action name, retrieve the strategy it is for from the DSL
  configuration.
  """
  @spec strategy_for_action(dsl_or_resource, atom) :: {:ok, Strategy.t()} | :error
  def strategy_for_action(dsl_or_resource, action_name) do
    case Extension.get_persisted(dsl_or_resource, {:authentication_action, action_name}) do
      nil -> :error
      value -> {:ok, value}
    end
  end

  @doc """
  Given an action name, retrieve the strategy it is for from the DSL
  configuration.
  """
  @spec strategy_for_action!(dsl_or_resource, atom) :: Strategy.t() | no_return
  def strategy_for_action!(dsl_or_resource, action_name) do
    case strategy_for_action(dsl_or_resource, action_name) do
      {:ok, value} ->
        value

      :error ->
        raise "No strategy action named `#{inspect(action_name)}` found on resource `#{inspect(dsl_or_resource)}`"
    end
  end
end
