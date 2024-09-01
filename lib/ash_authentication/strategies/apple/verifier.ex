defmodule AshAuthentication.Strategy.Apple.Verifier do
  @moduledoc """
  DSL verifier for Apple strategy.
  """

  alias AshAuthentication.Strategy.OAuth2
  import AshAuthentication.Validations

  @doc false
  @spec verify(OAuth2.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, _dsl_state) do
    with :ok <- validate_secret(strategy, :client_id),
         :ok <- validate_secret(strategy, :team_id),
         :ok <- validate_secret(strategy, :private_key_id),
         :ok <- validate_secret(strategy, :private_key_path) do
      validate_secret(strategy, :redirect_uri)
    end
  end
end
