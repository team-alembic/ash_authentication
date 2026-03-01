# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.HashProvider do
  @moduledoc """
  A behaviour providing password hashing.
  """

  @doc """
  Given some user input as a string, convert it into it's hashed form.
  """
  @callback hash(input :: String.t()) :: {:ok, hash :: String.t()} | :error

  @callback hash(input :: String.t(), salt :: String.t(), opts :: keyword()) ::
              {:ok, hash :: String.t()} | :error

  @doc """
  Check if the user input matches the hash.
  """
  @callback valid?(input :: String.t(), hash :: String.t()) :: boolean()

  @doc """
  Attempt to defeat timing attacks by simulating a password hash check.

  See [Bcrypt.no_user_verify/1](https://hexdocs.pm/bcrypt_elixir/Bcrypt.html#no_user_verify/1) for more information.
  """
  @callback simulate :: false

  @doc """
  Generate a salt for use with `hash/2`.
  """
  @callback gen_salt() :: String.t()

  @doc """
  Extract the salt from a previously generated hash.

  Used with shared-salt recovery codes to recover the salt from a stored hash
  for re-hashing during verification.
  """
  @callback extract_salt(hash :: String.t()) :: String.t() | :error

  @callback extract_iterations(hash :: String.t()) :: integer() | :error

  @optional_callbacks gen_salt: 0, hash: 3, extract_salt: 1, extract_iterations: 1
end
