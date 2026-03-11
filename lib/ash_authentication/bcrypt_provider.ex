# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.BcryptProvider do
  @moduledoc """
  Provides the default implementation of `AshAuthentication.HashProvider` using `Bcrypt`.
  """
  @behaviour AshAuthentication.HashProvider

  @doc """
  Given some user input as a string, convert it into it's hashed form using `Bcrypt`.

  ## Example

      iex> {:ok, hashed} = hash("Marty McFly")
      ...> String.starts_with?(hashed, "$2b$04$")
      true
  """
  @impl true
  @spec hash(String.t()) :: {:ok, String.t()} | :error
  if Code.ensure_loaded?(Bcrypt) do
    def hash(input) when is_binary(input), do: {:ok, Bcrypt.hash_pwd_salt(input)}
    def hash(_), do: :error
  else
    def hash(_), do: raise("Bcrypt is not available")
  end

  @doc """
  Check if the user input matches the hash.

  ## Example

      iex> valid?("Marty McFly", "$2b$04$qgacrnrAJz8aPwaVQiGJn.PvryldV.NfOSYYvF/CZAGgMvvzhIE7S")
      true

  """
  @impl true
  @spec valid?(input :: String.t() | nil, hash :: String.t()) :: boolean
  if Code.ensure_loaded?(Bcrypt) do
    def valid?(nil, _hash), do: Bcrypt.no_user_verify()

    def valid?(input, hash) when is_binary(input) and is_binary(hash),
      do: Bcrypt.verify_pass(input, hash)
  else
    def valid?(_input, _hash), do: raise("Bcrypt not available")
  end

  @doc """
  Generate a bcrypt salt for use with `hash/2`.
  """
  @impl true
  if Code.ensure_loaded?(Bcrypt) do
    def gen_salt do
      log_rounds = Application.get_env(:bcrypt_elixir, :log_rounds, 4)
      Bcrypt.Base.gen_salt(log_rounds)
    end
  else
    def gen_salt, do: raise("Bcrypt is not available")
  end

  @doc """
  Hash input with a specific salt, producing a deterministic result.
  """
  @impl true
  if Code.ensure_loaded?(Bcrypt) do
    def hash(input, salt, _opts \\ []) when is_binary(input) and is_binary(salt) do
      {:ok, Bcrypt.Base.hash_password(input, salt)}
    end
  else
    def hash(_input, _salt), do: raise("Bcrypt is not available")
  end

  @doc """
  Extract the salt from a bcrypt hash.

  Bcrypt hashes have the format `$2b$XX$<22-char-salt><31-char-hash>`.
  The salt portion (including algorithm and cost prefix) is the first 29 characters.
  """
  @impl true
  def extract_salt(hash) when is_binary(hash) do
    String.slice(hash, 0, 29)
  end

  @doc """
  Simulate a password check to help avoid timing attacks.

  ## Example

      iex> simulate()
      false
  """
  @impl true
  @spec simulate :: false
  if Code.ensure_loaded?(Bcrypt) do
    def simulate, do: Bcrypt.no_user_verify()
  else
    def simulate, do: raise("Bcrypt not available")
  end
end
