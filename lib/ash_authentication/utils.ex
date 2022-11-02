defmodule AshAuthentication.Utils do
  @moduledoc false
  alias Ash.Resource
  alias Spark.Dsl.Transformer

  @spec to_sentence(Enum.t(), [
          {:separator, String.t()} | {:final, String.t()} | {:whitespace, boolean}
        ]) :: String.t()
  def to_sentence(elements, opts \\ []) do
    opts =
      [separator: ",", final: "and", whitespace: true]
      |> Keyword.merge(opts)
      |> Map.new()

    if Enum.count(elements) == 1 do
      elements
      |> Enum.to_list()
      |> hd()
      |> to_string()
    else
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
  def maybe_append(collection, test, _element) when test in [nil, false], do: collection
  def maybe_append(collection, _test, element), do: Enum.concat(collection, [element])

  @doc """
  Used within transformers to optionally build actions as needed.
  """
  @spec maybe_build_action(map, atom, (map -> map)) :: {:ok, atom | map} | {:error, any}
  def maybe_build_action(dsl_state, action_name, builder) when is_function(builder, 1) do
    with nil <- Resource.Info.action(dsl_state, action_name),
         {:ok, action} <- builder.(dsl_state) do
      {:ok, Transformer.add_entity(dsl_state, [:actions], action)}
    else
      action when is_map(action) -> {:ok, dsl_state}
      {:error, reason} -> {:error, reason}
    end
  end
end
