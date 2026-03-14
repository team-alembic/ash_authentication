# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Otp.DefaultGenerator do
  @moduledoc """
  Default OTP code generator.

  Generates random codes from a configurable character set and length.
  Also provides `normalize/1` for case-insensitive matching.

  Ambiguous characters are excluded to avoid confusion when users read
  and type codes:

  - Letters removed: `I` (looks like `1`/`l`), `L` (looks like `1`/`I`),
    `O` (looks like `0`), `S` (looks like `5`), `Z` (looks like `2`)
  - Digits removed: `0` (looks like `O`), `1` (looks like `I`/`l`),
    `2` (looks like `Z`), `5` (looks like `S`)
  """

  # Excludes I, L, O, S, Z
  @uppercase_letters ~c"ABCDEFGHJKMNPQRTUVWXY"
  # Excludes 0, 1, 2, 5
  @digits ~c"346789"
  @uppercase_alphanumeric @uppercase_letters ++ @digits

  @doc """
  Generate a random OTP code.

  Options:
    * `:length` - the length of the code (default: 6)
    * `:characters` - the character set to use (default: `:uppercase_letters`)
      Supported values: `:uppercase_letters`, `:digits`, `:uppercase_alphanumeric`
  """
  @spec generate(keyword) :: String.t()
  def generate(opts \\ []) do
    length = Keyword.get(opts, :length, 6)
    characters = character_set(Keyword.get(opts, :characters, :uppercase_letters))

    1..length
    |> Enum.map(fn _ -> Enum.random(characters) end)
    |> List.to_string()
  end

  @doc """
  Normalize an OTP code for comparison.

  Trims whitespace and converts to uppercase.
  """
  @spec normalize(String.t()) :: String.t()
  def normalize(code) when is_binary(code) do
    code
    |> String.trim()
    |> String.upcase()
  end

  defp character_set(:uppercase_letters), do: @uppercase_letters
  defp character_set(:digits), do: @digits
  defp character_set(:uppercase_alphanumeric), do: @uppercase_alphanumeric
end
