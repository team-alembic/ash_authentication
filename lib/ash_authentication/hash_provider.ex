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
end
