defmodule AshAuthentication.Validations do
  @moduledoc """
  Common validations shared by several transformers.
  """

  import AshAuthentication.{Sender, Utils}
  alias Ash.Resource.Attribute
  alias Spark.{Dsl, Dsl.Transformer, Error.DslError}

  @doc """
  Given a map validate that the provided field is one of the values provided.
  """
  @spec validate_field_in_values(map, any, [any]) :: :ok | {:error, String.t()}
  def validate_field_in_values(map, field, []) when is_map(map) when is_map_key(map, field),
    do: {:error, "Expected `#{inspect(field)}` to not be present."}

  def validate_field_in_values(map, _field, []) when is_map(map), do: :ok

  def validate_field_in_values(map, field, [value])
      when is_map(map) and is_map_key(map, field) and :erlang.map_get(field, map) == value,
      do: :ok

  def validate_field_in_values(map, field, [value]) when is_map(map) and is_map_key(map, field),
    do: {:error, "Expected `#{inspect(field)}` to equal `#{inspect(value)}`"}

  def validate_field_in_values(map, field, values)
      when is_map(map) and is_list(values) and is_map_key(map, field) do
    if Map.get(map, field) in values do
      :ok
    else
      values =
        values
        |> Enum.map(&"`#{inspect(&1)}`")
        |> to_sentence(final: "or")

      {:error, "Expected `#{inspect(field)}` to be one of #{values}"}
    end
  end

  def validate_field_in_values(map, field, [value]) when is_map(map),
    do: {:error, "Expected `#{inspect(field)}` to be present and equal `#{inspect(value)}`"}

  def validate_field_in_values(map, field, values) when is_map(map) and is_list(values) do
    values =
      values
      |> Enum.map(&"`#{inspect(&1)}`")
      |> to_sentence(final: "or")

    {:error, "Expected `#{inspect(field)}` to be present and contain one of #{values}"}
  end

  @doc """
  Given a map, validate that the provided field predicate returns true for the value.
  """
  @spec validate_field_with(map, field, (any -> boolean), message) :: :ok | {:error, message}
        when field: any, message: any
  def validate_field_with(map, field, predicate, message \\ nil) do
    okay? =
      map
      |> Map.get(field)
      |> predicate.()

    cond do
      okay? ->
        :ok

      message ->
        {:error, message}

      true ->
        {:error, "Field `#{inspect(field)}` in map `#{inspect(map)}` failed validation."}
    end
  end

  @doc """
  Find and return a named attribute in the DSL state.
  """
  @spec find_attribute(Dsl.t(), atom) ::
          {:ok, Attribute.t()} | {:error, Exception.t()}
  def find_attribute(dsl_state, attribute_name) do
    dsl_state
    |> Transformer.get_entities([:attributes])
    |> Enum.find(&(&1.name == attribute_name))
    |> case do
      nil ->
        resource = Transformer.get_persisted(dsl_state, :module)

        {:error,
         DslError.exception(
           path: [:attributes, :attribute],
           message:
             "The resource `#{inspect(resource)}` does not define an attribute named `#{inspect(attribute_name)}`"
         )}

      attribute ->
        {:ok, attribute}
    end
  end

  @doc """
  Find and return a persisted option in the DSL state.
  """
  @spec persisted_option(Dsl.t(), atom) :: {:ok, any} | {:error, {:unknown_persisted, atom}}
  def persisted_option(dsl_state, option) do
    case Transformer.get_persisted(dsl_state, option) do
      nil -> {:error, {:unknown_persisted, option}}
      value -> {:ok, value}
    end
  end

  @doc """
  Ensure that token generation is enabled for the resource.
  """
  @spec validate_token_generation_enabled(Dsl.t(), binary) :: :ok | {:error, Exception.t()}
  def validate_token_generation_enabled(dsl_state, message) do
    if AshAuthentication.Info.authentication_tokens_enabled?(dsl_state),
      do: :ok,
      else: {:error, DslError.exception(path: [:tokens], message: message)}
  end

  @doc """
  Ensure that the named module implements a specific behaviour.
  """
  @spec validate_behaviour(module, module) :: :ok | {:error, Exception.t()}
  def validate_behaviour(module, behaviour) do
    if Spark.implements_behaviour?(module, behaviour) do
      :ok
    else
      {:error,
       DslError.exception(
         path: [:password_reset],
         message: "`#{inspect(module)}` must implement the `#{inspect(behaviour)}` behaviour."
       )}
    end
  end

  @doc """
  Validates that `extension` is present on the resource.
  """
  @spec validate_extension(Dsl.t(), module) :: :ok | {:error, Exception.t()}
  def validate_extension(dsl_state, extension) do
    extensions = Transformer.get_persisted(dsl_state, :extensions, [])

    if extension in extensions,
      do: :ok,
      else:
        {:error,
         DslError.exception(
           path: [:extensions],
           message:
             "The `#{inspect(extension)}` extension must also be present on this resource for password authentication to work."
         )}
  end

  @doc """
  Build an attribute if not present.
  """
  @spec maybe_build_attribute(Dsl.t(), atom, (Dsl.t() -> {:ok, Attribute.t()})) :: {:ok, Dsl.t()}
  def maybe_build_attribute(dsl_state, attribute_name, builder) do
    with {:error, _} <- find_attribute(dsl_state, attribute_name),
         {:ok, attribute} <- builder.(dsl_state) do
      {:ok, Transformer.add_entity(dsl_state, [:attributes], attribute)}
    else
      {:ok, attribute} when is_struct(attribute, Attribute) -> {:ok, dsl_state}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Validate that a "secret" field is configured correctly.
  """
  def validate_secret(strategy, option, allowed_extras \\ []) do
    value = Map.get(strategy, option)

    cond do
      is_binary(value) ->
        :ok

      value in allowed_extras ->
        :ok

      is_tuple(value) and tuple_size(value) == 2 ->
        validate_behaviour(elem(value, 0), AshAuthentication.Secret)

      true ->
        message =
          case allowed_extras do
            [] ->
              "Expected `#{inspect(option)}` to be a string or a module which implements the `AshAuthentication.Secret` behaviour."

            _ ->
              options = Enum.map_join(allowed_extras, ", ", &"`#{inspect(&1)}`")

              "Expected `#{inspect(option)}` to be #{options}, a string or a module which implements the `AshAuthentication.Secret` behaviour."
          end

        {:error,
         DslError.exception(path: [:authentication, :strategies, strategy.name], message: message)}
    end
  end
end
