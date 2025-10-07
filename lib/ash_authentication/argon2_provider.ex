# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Argon2Provider do
  @moduledoc """
  Provides an implementation of `AshAuthentication.HashProvider` using `Argon2`.
  """
  @behaviour AshAuthentication.HashProvider

  @doc """
  Given some user input as a string, convert it into it's hashed form using `Argon2`.

  ## Example

      iex> {:ok, hashed} = hash("Marty McFly")
      ...> String.starts_with?(hashed, "$argon2id$")
      true
  """
  @impl true
  @spec hash(String.t()) :: {:ok, String.t()} | :error
  if Code.ensure_loaded?(Argon2) do
    def hash(input) when is_binary(input), do: {:ok, Argon2.hash_pwd_salt(input)}
    def hash(_input), do: :error
  else
    def hash(_input), do: raise("Argon2 is not available")
  end

  @doc """
  Check if the user input matches the hash.

  ## Example

      iex> valid?("Marty McFly", "$argon2id$v=19$m=256,t=1,p=2$T9zYADIg2xF5P21FgyIX5g$5K1vy8VTMlEZUWuO8HPOJcu239FkHen5XKmg7uviHEk")
      true
  """
  @impl true
  @spec valid?(input :: String.t() | nil, hash :: String.t()) :: boolean()
  if Code.ensure_loaded?(Argon2) do
    def valid?(nil, _hash), do: Argon2.no_user_verify()

    def valid?(input, hash) when is_binary(input) and is_binary(hash),
      do: Argon2.verify_pass(input, hash)
  else
    def valid?(_input, _hash), do: raise("Argon2 is not available")
  end

  @doc """
  Simulate a password check to help avoid timing attacks.

  ## Example

      iex> simulate()
      false
  """
  @impl true
  @spec simulate :: false
  if Code.ensure_loaded?(Argon2) do
    def simulate, do: Argon2.no_user_verify()
  else
    def simulate, do: raise("Argon2 is not available")
  end
end
