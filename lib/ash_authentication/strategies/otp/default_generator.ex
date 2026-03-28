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
  @unambiguous_uppercase ~c"ABCDEFGHJKMNPQRTUVWXY"
  # Excludes 0, 1, 2, 5
  @unambiguous_digits ~c"346789"
  @unambiguous_alphanumeric @unambiguous_uppercase ++ @unambiguous_digits
  @digits_only ~c"0123456789"
  @uppercase_letters_only ~c"ABCDEFGHIJKLMNOPQRSTUVWXYZ"

  @doc """
  Generate a random OTP code.

  Options:
    * `:length` - the length of the code (default: 6)
    * `:characters` - the character set to use (default: `:unambiguous_uppercase`)
      Supported values: `:unambiguous_uppercase`, `:unambiguous_alphanumeric`, `:digits_only`, `:uppercase_letters_only`
  """
  @spec generate(keyword) :: String.t()
  def generate(opts \\ []) do
    code_length = Keyword.get(opts, :length, 6)
    characters = character_set(Keyword.get(opts, :characters, :unambiguous_uppercase))
    alphabet_size = length(characters)
    chars_tuple = List.to_tuple(characters)

    # Maximum byte value that ensures uniform distribution (avoids modulo bias).
    # Bytes in bias_limit..255 are discarded.
    bias_limit = 256 - rem(256, alphabet_size)

    # Request 2× the needed bytes to have a buffer for rejected values.
    :crypto.strong_rand_bytes(code_length * 2)
    |> :binary.bin_to_list()
    |> Enum.filter(&(&1 < bias_limit))
    |> case do
      filtered when length(filtered) >= code_length ->
        filtered
        |> Enum.take(code_length)
        |> Enum.map(&elem(chars_tuple, rem(&1, alphabet_size)))
        |> List.to_string()

      _ ->
        # Will never happen in practice, but in case we didn't get enough valid values for
        # our alphabet, just try again.
        generate(opts)
    end
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

  defp character_set(:unambiguous_uppercase), do: @unambiguous_uppercase
  defp character_set(:unambiguous_alphanumeric), do: @unambiguous_alphanumeric
  defp character_set(:digits_only), do: @digits_only
  defp character_set(:uppercase_letters_only), do: @uppercase_letters_only
end
