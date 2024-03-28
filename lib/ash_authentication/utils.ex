defmodule AshAuthentication.Utils do
  @moduledoc false
  alias Ash.{Domain, Resource}
  alias Spark.{Dsl, Dsl.Transformer}

  @doc """
  Returns `true` if `falsy` is either `nil` or `false`.
  """
  @spec is_falsy(any) :: Macro.t()
  defguard is_falsy(falsy) when falsy in [nil, false]

  @doc """
  Returns `false` if `truthy` is either `nil` or `false`.
  """
  @spec is_truthy(any) :: Macro.t()
  defguard is_truthy(truthy) when truthy not in [nil, false]

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
  Optionally concat a collection to another collection.

  When `test` is truthy, concat the collections together.
  """
  @spec maybe_concat(Enum.t(), test :: any, Enum.t()) :: Enum.t()
  def maybe_concat(collection, test, _new_elements) when is_falsy(test), do: collection
  def maybe_concat(collection, _test, new_elements), do: Enum.concat(collection, new_elements)

  @doc """
  Used within transformers to infer `domain` from a resource if the option is not set.
  """
  def maybe_set_domain(dsl_state, section) do
    domain = Transformer.get_persisted(dsl_state, :domain)

    if domain && !Transformer.get_option(dsl_state, [section], :domain) do
      {:ok, Transformer.set_option(dsl_state, [section], :domain, domain)}
    else
      {:ok, dsl_state}
    end
  end

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

  @doc """
  Like `maybe_set_field/3` except that the value is lazily generated.
  """
  @spec maybe_set_field_lazy(input, any, (input -> value)) :: map when input: map, value: any
  def maybe_set_field_lazy(map, field, generator)
      when is_falsy(:erlang.map_get(field, map)) and is_function(generator, 1),
      do: Map.put(map, field, generator.(map))

  def maybe_set_field_lazy(map, _field, _generator), do: map

  @doc """
  Asserts that `resource` is an Ash resource and `extension` is a Spark DSL
  extension.
  """
  @spec assert_resource_has_extension(Resource.t(), Spark.Dsl.Extension.t()) ::
          :ok | {:error, term}
  def assert_resource_has_extension(resource, extension) do
    with :ok <- assert_is_resource(resource) do
      assert_has_extension(resource, extension)
    end
  end

  @doc """
  Asserts that `module` is actually an Ash resource.
  """
  @spec assert_is_resource(Resource.t()) :: :ok | {:error, term}
  def assert_is_resource(module) do
    with :ok <- assert_is_module(module),
         true <- function_exported?(module, :spark_is, 0),
         Resource <- module.spark_is() do
      :ok
    else
      _ ->
        {:error, "Module `#{inspect(module)}` is not an Ash resource"}
    end
  end

  @doc """
  Asserts that `module` is actually an Ash domain.
  """
  @spec assert_is_domain(Domain.t()) :: :ok | {:error, term}
  def assert_is_domain(module) do
    with :ok <- assert_is_module(module),
         true <- function_exported?(module, :spark_is, 0),
         Domain <- module.spark_is() do
      :ok
    else
      _ -> {:error, "Module `#{inspect(module)}` is not an Ash domain"}
    end
  end

  @doc """
  Asserts that `module` is a Spark DSL extension.
  """
  @spec assert_is_extension(Spark.Dsl.Extension.t()) :: :ok | {:error, term}
  def assert_is_extension(extension) do
    with :ok <- assert_is_module(extension) do
      assert_has_behaviour(extension, Spark.Dsl.Extension)
    end
  end

  @doc """
  Asserts that `module` is actually a module.
  """
  @spec assert_is_module(module) :: :ok | {:error, term}
  def assert_is_module(module) when is_atom(module) do
    case Code.ensure_compiled(module) do
      {:module, _} -> :ok
      _ -> {:error, "Argument `#{inspect(module)}` is not a valid module"}
    end
  end

  def assert_is_module(module),
    do: {:error, "Argument `#{inspect(module)}` is not a valid module"}

  @doc """
  Asserts that `module` is extended by `extension`.
  """
  @spec assert_has_extension(Resource.t(), Spark.Dsl.Extension.t()) :: :ok | {:error, term}
  def assert_has_extension(module, extension) do
    if extension in Spark.extensions(module) do
      :ok
    else
      {:error, "Module `#{inspect(module)}` is not extended by `#{inspect(extension)}`"}
    end
  end

  @doc """
  Asserts that `module` implements `behaviour`.
  """
  @spec assert_has_behaviour(module, module) :: :ok | {:error, term}
  def assert_has_behaviour(module, behaviour) do
    if Spark.implements_behaviour?(module, behaviour) do
      :ok
    else
      {:error,
       "Module `#{inspect(module)}` does not implement the `#{inspect(behaviour)}` behaviour"}
    end
  end
end
