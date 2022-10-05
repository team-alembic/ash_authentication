defmodule AshAuthentication.Utils do
  @moduledoc false

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
  Generate the AST for an options function spec.

  Not something you should ever need.
  """
  @spec spec_for_option(keyword) :: Macro.t()
  def spec_for_option(options) do
    result_type =
      case Keyword.get(options, :type, :term) do
        {:behaviour, _module} ->
          :module

        terminal ->
          terminal
      end

    {result_type, [], Elixir}
  end
end
