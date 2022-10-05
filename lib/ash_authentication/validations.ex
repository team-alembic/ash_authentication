defmodule AshAuthentication.Validations do
  @moduledoc """
  Common validations shared by several transformers.
  """

  import AshAuthentication.Utils

  @doc """
  Given a map validate that the provided field is one of the values provided.
  """
  def validate_field_in_values(map, field, values) when is_map(map) and is_list(values) do
    with {:ok, value} <- Map.fetch(map, field),
         true <- value in values do
      :ok
    else
      :error ->
        {:error, "Expected map to have a field named `#{inspect(field)}`"}

      false ->
        values =
          values
          |> Enum.map(&"`#{inspect(&1)}`")
          |> to_sentence(final: "or")

        {:error, "Expected `#{inspect(field)}` to be one of #{values}"}
    end
  end
end
