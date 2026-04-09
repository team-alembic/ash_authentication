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
  Hash with action context.

  An optional variant of `hash/1` that receives the Ash context from the
  current action (changeset or action input). This enables hash providers
  that need external state — for example, a shared-salt provider can read
  a pre-generated salt from the context.

  When implemented, this callback is preferred over `hash/1` by the
  recovery code strategy's hashing change and verify action.
  """
  @callback hash(input :: String.t(), context :: map()) ::
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

  @optional_callbacks hash: 2

  @doc """
  Calls `hash/2` if the provider implements it, otherwise falls back to `hash/1`.
  """
  @spec call_hash(module(), String.t(), map()) :: {:ok, String.t()} | :error
  def call_hash(provider, input, context) do
    if function_exported?(provider, :hash, 2) do
      provider.hash(input, context)
    else
      provider.hash(input)
    end
  end
end
