defmodule AshAuthentication.Strategy.Oidc.Transformer do
  @moduledoc """
  DSL transformer for oidc strategies.

  Adds a nonce generator to the strategy if `nonce` is set to `true`.
  Delegates to the default OAuth2 transformer.
  """

  alias AshAuthentication.Strategy.{OAuth2, Oidc.NonceGenerator}

  @doc false
  @spec transform(OAuth2.t(), map) :: {:ok, OAuth2.t() | map} | {:error, Exception.t()}
  def transform(strategy, dsl_state) when strategy.nonce == true do
    strategy
    |> Map.put(:nonce, {NonceGenerator, []})
    |> Map.put(:provider, :oidc)
    |> OAuth2.transform(dsl_state)
  end

  def transform(strategy, dsl_state), do: OAuth2.transform(strategy, dsl_state)
end
