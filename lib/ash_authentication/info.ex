defmodule AshAuthentication.Info do
  @moduledoc """
  Generated configuration functions based on a resource's DSL configuration.
  """

  use AshAuthentication.InfoGenerator,
    extension: AshAuthentication,
    sections: [:authentication]

  @doc """
  Retrieve a named strategy from a resource.
  """
  @spec strategy(dsl_or_resource :: map | module, atom) :: {:ok, strategy} | :error
        when strategy: struct
  def strategy(dsl_or_resource, name) do
    dsl_or_resource
    |> authentication_strategies()
    |> Enum.find_value(:error, fn strategy ->
      if strategy.name == name, do: {:ok, strategy}
    end)
  end

  @doc """
  Retrieve a named strategy from a resource (raising version).
  """
  @spec strategy!(dsl_or_resource :: map | module, atom) :: strategy | no_return
        when strategy: struct
  def strategy!(dsl_or_resource, name) do
    case strategy(dsl_or_resource, name) do
      {:ok, strategy} ->
        strategy

      :error ->
        raise "No strategy named `#{inspect(name)}` found on resource `#{inspect(dsl_or_resource)}`"
    end
  end
end
