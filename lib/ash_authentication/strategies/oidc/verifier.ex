defmodule AshAuthentication.Strategy.Oidc.Verifier do
  @moduledoc """
  DSL verifier for OpenID Connect strategy.
  """

  alias AshAuthentication.Strategy.OAuth2
  import AshAuthentication.Validations

  @doc false
  @spec verify(OAuth2.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, _dsl_state) do
    with :ok <- validate_secret(strategy, :client_id),
         :ok <- validate_secret(strategy, :client_secret),
         :ok <- validate_secret(strategy, :base_url),
         :ok <- validate_secret(strategy, :nonce, [true, false]) do
      if strategy.auth_method == :private_key_jwt do
        validate_secret(strategy, :private_key)
      else
        :ok
      end
    end
  end
end
