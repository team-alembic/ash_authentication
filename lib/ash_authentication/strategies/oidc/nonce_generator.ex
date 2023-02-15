defmodule AshAuthentication.Strategy.Oidc.NonceGenerator do
  @moduledoc """
  An implmentation of `AshAuthentication.Secret` that generates nonces for
  OpenID Connect strategies.

  Defaults to `16` bytes of random data.  You can change this by setting the
  `byte_size` option in your DSL:

  ```elixir
  oidc do
    nonce {AshAuthentication.NonceGenerator, byte_size: 32}
    # ...
  end
  ```
  """

  use AshAuthentication.Secret

  @doc false
  @impl true
  @spec secret_for(secret_name :: [atom], Ash.Resource.t(), keyword) :: {:ok, String.t()} | :error
  def secret_for(_secret_name, _resource, opts) do
    opts
    |> Keyword.get(:byte_size, 16)
    |> :crypto.strong_rand_bytes()
    |> Base.encode64(padding: false)
    |> then(&{:ok, &1})
  end
end
