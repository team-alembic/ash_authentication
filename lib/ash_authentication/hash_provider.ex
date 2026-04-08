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
  The minimum bits of input entropy required for this hash provider to be safe.

  Slow hash providers like bcrypt and argon2 return `0` because their
  computational cost makes brute-force attacks impractical regardless of input
  entropy. Fast deterministic hash providers like SHA-256 require high-entropy
  inputs (e.g. 60+ bits) because their speed makes low-entropy inputs
  vulnerable to offline brute-force attacks.
  """
  @callback minimum_entropy() :: non_neg_integer()

  @doc """
  Whether the same input always produces the same hash output.

  Deterministic providers (e.g. SHA-256) allow atomic database-level
  verification by hashing the input and matching directly against stored
  values. Non-deterministic providers (e.g. bcrypt, argon2) use random salts,
  so verification requires loading stored hashes and comparing individually.
  """
  @callback deterministic?() :: boolean()
end
