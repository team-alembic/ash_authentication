defmodule AshAuthentication.Info do
  @moduledoc """
  Generated configuration functions based on a resource's DSL configuration.
  """

  use Spark.InfoGenerator,
    extension: AshAuthentication,
    sections: [:authentication]

  alias Ash.{Changeset, Domain, Query, Resource}
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

  @doc """
  Find the underlying strategy that required a change/preparation to be used.

  This is because the `strategy_name` can be passed on the change options, eg:

  ```elixir
  change {AshAuthentication.Strategy.Password.HashPasswordChange, strategy_name: :banana_custard}
  ```

  Or via the action context, eg:

  ```elixir
  prepare set_context(%{strategy_name: :banana_custard})
  prepare AshAuthentication.Strategy.Password.SignInPreparation
  ```

  Or via the passed-in context on calling the action.
  """
  @spec find_strategy(Query.t() | Changeset.t(), context, options) :: {:ok, Strategy.t()} | :error
        when context: map, options: Keyword.t()
  def find_strategy(queryset, context \\ %{}, options) do
    with :error <- Keyword.fetch(options, :strategy_name),
         :error <- Map.fetch(context, :strategy_name),
         :error <- Map.fetch(queryset.context, :strategy_name),
         :error <- strategy_for_action(queryset.resource, queryset.action.name) do
      :error
    else
      {:ok, strategy_name} when is_atom(strategy_name) ->
        strategy(queryset.resource, strategy_name)

      {:ok, strategy} ->
        {:ok, strategy}
    end
  end

  @doc """
  Retrieve the domain to use for authentication.

  If the `authentication.domain` DSL option is set, it will be used, otherwise
  it will default to that configured on the resource.
  """
  @spec domain(dsl_or_resource) :: {:ok, Domain.t()} | :error
  def domain(dsl_or_resource) do
    auth_domain =
      case authentication_domain(dsl_or_resource) do
        {:ok, value} -> value
        :error -> nil
      end

    resource_domain = Resource.Info.domain(dsl_or_resource)

    domain = auth_domain || resource_domain

    if domain, do: {:ok, domain}, else: :error
  end

  @doc "Raising version of `domain/1`"
  def domain!(dsl_or_resource) do
    case domain(dsl_or_resource) do
      {:ok, value} -> value
      :error -> raise "No `domain` configured on resource `#{inspect(dsl_or_resource)}`"
    end
  end
end
