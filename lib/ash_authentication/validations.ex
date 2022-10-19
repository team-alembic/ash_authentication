defmodule AshAuthentication.Validations do
  @moduledoc """
  Common validations shared by several transformers.
  """

  import AshAuthentication.Utils

  @doc """
  Given a map validate that the provided field is one of the values provided.
  """
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
        nil
    end)
  end
end
