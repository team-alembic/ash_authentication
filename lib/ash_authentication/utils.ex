defmodule AshAuthentication.Utils do
  @moduledoc false
  alias Ash.Resource
  alias Spark.{Dsl, Dsl.Transformer}

  @doc """
  Returns true if `falsy` is either `nil` or `false`.
  """
  @spec is_falsy(any) :: Macro.t()
  defguard is_falsy(falsy) when falsy in [nil, false]

  @doc """
  Convert a list of `String.Chars.t` into a sentence.

  ## Example

      iex> ~w[Marty Doc Einstein] |> to_sentence()
      "Marty, Doc and Einstein"

  """
  @spec to_sentence(Enum.t(), [
          {:separator, String.t()} | {:final, String.t()} | {:whitespace, boolean}
        ]) :: String.t()
  def to_sentence(elements, opts \\ []) do
    opts =
      [separator: ",", final: "and", whitespace: true]
      |> Keyword.merge(opts)
      |> Map.new()

    elements
    |> Enum.to_list()
    |> case do
      [] ->
        ""

      [element] ->
        to_string(element)

      [_ | _] = elements ->
        elements
        |> Enum.reverse()
        |> convert_to_sentence("", opts.separator, opts.final, opts.whitespace)
    end
  end

  defp convert_to_sentence([last], result, _, final, true), do: "#{result} #{final} #{last}"
  defp convert_to_sentence([last], result, _, final, false), do: "#{result}#{final}#{last}"

  defp convert_to_sentence([next | rest], "", sep, final, ws),
    do: convert_to_sentence(rest, to_string(next), sep, final, ws)

  defp convert_to_sentence([next | rest], result, sep, final, true),
    do: convert_to_sentence(rest, "#{result}#{sep} #{next}", sep, final, true)

  defp convert_to_sentence([next | rest], result, sep, final, false),
    do: convert_to_sentence(rest, "#{result}#{sep}#{next}", sep, final, false)

  @doc """
  Optionally append an element to a collection.

  When `test` is truthy, append `element` to the collection.
  """
  @spec maybe_append(Enum.t(), test :: any, element :: any) :: Enum.t()
  def maybe_append(collection, test, _element) when is_falsy(test), do: collection
  def maybe_append(collection, _test, element), do: Enum.concat(collection, [element])

  @doc """
  Used within transformers to optionally build actions as needed.
  """
  @spec maybe_build_action(Dsl.t(), atom, (map -> map)) :: {:ok, atom | map} | {:error, any}
  def maybe_build_action(dsl_state, action_name, builder) when is_function(builder, 1) do
    with nil <- Resource.Info.action(dsl_state, action_name),
         {:ok, action} <- builder.(dsl_state) do
      {:ok, Transformer.add_entity(dsl_state, [:actions], action)}
    else
      action when is_map(action) -> {:ok, dsl_state}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Used within transformers to optionally build attributes as needed.
  """
  @spec maybe_build_attribute(Dsl.t(), atom, atom | module, keyword) :: {:ok, Dsl.t()}
  def maybe_build_attribute(dsl_state, name, type, options) do
    if Resource.Info.attribute(dsl_state, name) do
      {:ok, dsl_state}
    else
      options =
        options
        |> Keyword.put(:name, name)
        |> Keyword.put(:type, type)

      attribute = Transformer.build_entity!(Resource.Dsl, [:attributes], :attribute, options)

      {:ok, Transformer.add_entity(dsl_state, [:attributes], attribute)}
    end
  end

  @doc """
  Used within transformers to optionally build relationships as needed.
  """
  @spec maybe_build_relationship(
          Dsl.t(),
          relationship_name :: atom,
          (Dsl.t() -> {:ok, Resource.Relationships.relationship()})
        ) :: {:ok, Dsl.t()} | {:error, Exception.t()}
  def maybe_build_relationship(dsl_state, relationship_name, builder)
      when is_function(builder, 1) do
    with :error <- find_relationship(dsl_state, relationship_name),
         {:ok, relationship} <- builder.(dsl_state) do
      {:ok, Transformer.add_entity(dsl_state, [:relationships], relationship)}
    else
      {:ok, _relationship} -> {:ok, dsl_state}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Find a relationship from a resource.
  """
  @spec find_relationship(Dsl.t(), relationship_name :: atom) ::
          {:ok, Resource.Relationships.relationship()} | :error
  def find_relationship(dsl_state, relationship_name) do
    dsl_state
    |> Resource.Info.relationships()
    |> Enum.find(&(&1.name == relationship_name))
    |> case do
      nil -> :error
      relationship -> {:ok, relationship}
    end
  end

  @doc """
  Optionally set a field in a map.

  Like `Map.put_new/3` except that it overwrites fields if their contents are
  falsy.
  """
  @spec maybe_set_field(map, any, any) :: map
  def maybe_set_field(map, field, value) when is_falsy(:erlang.map_get(field, map)),
    do: Map.put(map, field, value)

  def maybe_set_field(map, _field, _value), do: map

  def maybe_set_field_lazy(map, field, generator)
      when is_falsy(:erlang.map_get(field, map)) and is_function(generator, 1),
      do: Map.put(map, field, generator.(map))

  def maybe_set_field_lazy(map, _field, _generator), do: map
end
