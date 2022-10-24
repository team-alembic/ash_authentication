defmodule AshAuthentication.Validations do
  @moduledoc """
  Common validations shared by several transformers.
  """

  import AshAuthentication.Utils
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
    do: {:error, "Expected `#{inspect(field)}` to contain `#{inspect(value)}`"}

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
    do: {:error, "Expected `#{inspect(field)}` to be present and contain `#{inspect(value)}`"}

  def validate_field_in_values(map, field, values) when is_map(map) and is_list(values) do
    values =
      values
      |> Enum.map(&"`#{inspect(&1)}`")
      |> to_sentence(final: "or")

    {:error, "Expected `#{inspect(field)}` to be present and contain one of #{values}"}
  end

  @doc """
  Validates the uniqueness of all subject names per otp app.
  """
  @spec validate_unique_subject_names(module) :: :ok | no_return
  def validate_unique_subject_names(otp_app) do
    otp_app
    |> AshAuthentication.authenticated_resources()
    |> Enum.group_by(& &1.subject_name)
    |> Enum.each(fn
      {subject_name, configs} when length(configs) > 1 ->
        resources =
          configs
          |> Enum.map(&"`#{inspect(&1.resource)}`")
          |> AshAuthentication.Utils.to_sentence()

        raise "Error: multiple resources use the `#{subject_name}` subject name: #{resources}"

      _ ->
        :ok
    end)
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
end
