# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Base do
  @moduledoc false

  @base62 Enum.with_index(Enum.concat([?a..?z, ?A..?Z, ?0..?9]))

  @doc false
  def encode62(""), do: ""

  # We don't deal with leading null bytes
  def encode62(<<0>> <> _), do: raise(ArgumentError)

  def encode62(value) when is_binary(value) do
    value
    |> :crypto.bytes_to_integer()
    |> encode62()
  end

  for {char, i} <- @base62 do
    def encode62(unquote(i)), do: unquote(<<char>>)
  end

  def encode62(v) do
    encode62(div(v, 62)) <> encode62(rem(v, 62))
  end

  @doc false

  def bindecode62(""), do: {:ok, ""}

  def bindecode62(binary) do
    binary
    |> do_bindecode62([])
    |> Integer.undigits(62)
    |> Integer.digits(256)
    |> :binary.list_to_bin()
    |> then(&{:ok, &1})
  rescue
    _ ->
      :error
  end

  defp do_bindecode62(<<>>, digits) do
    Enum.reverse(digits)
  end

  defp do_bindecode62(<<char>>, digits) do
    Enum.reverse([decode_char62(char) | digits])
  end

  defp do_bindecode62(<<char, rest::binary>>, digits) do
    do_bindecode62(rest, [decode_char62(char) | digits])
  end

  @doc false
  def decode62(""), do: {:ok, 0}

  def decode62(binary) do
    binary
    |> String.split("", trim: true)
    |> Enum.reverse()
    |> do_decode62({0, 0})
    |> then(&{:ok, &1})
  rescue
    _ -> :error
  end

  defp do_decode62([char], {index, sum}) do
    sum + charval62(char, index)
  end

  defp do_decode62([char | rest], {index, sum}) do
    do_decode62(rest, {index + 1, sum + charval62(char, index)})
  end

  for {char, i} <- @base62 do
    defp decode_char62(unquote(<<char>>)), do: unquote(i)
    defp decode_char62(unquote(char)), do: unquote(i)
  end

  defp decode_char62(char) do
    raise "invalid char #{char}"
  end

  defp charval62(char, index) do
    decode_char62(char) * Integer.pow(62, index)
  end
end
