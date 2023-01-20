defmodule AshAuthentication.Strategy.OAuth2.Verifier do
  @moduledoc """
  DSL verifier for oauth2 strategies.
  """

  alias AshAuthentication.{Secret, Strategy.OAuth2}
  alias Spark.Error.DslError
  import AshAuthentication.Validations

  @doc false
  @spec verify(OAuth2.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, _dsl_state) do
    with :ok <- validate_secret(strategy, :authorize_url),
         :ok <- validate_secret(strategy, :client_id),
         :ok <- validate_secret(strategy, :client_secret),
         :ok <- validate_secret(strategy, :redirect_uri),
         :ok <- validate_secret(strategy, :site),
         :ok <- validate_secret(strategy, :token_url),
         :ok <- validate_secret(strategy, :user_url) do
      validate_secret(strategy, :private_key, strategy.auth_method != :private_key_jwt)
    end
  end

  defp validate_secret(strategy, option, allow_nil \\ false) do
    case Map.fetch(strategy, option) do
      {:ok, value} when is_binary(value) ->
        :ok

      {:ok, nil} when allow_nil ->
        :ok

      {:ok, {module, _}} when is_atom(module) ->
        validate_behaviour(module, Secret)

      _ ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, :oauth2],
           message:
             "Expected `#{inspect(option)}` to be either a string or a module which implements the `AshAuthentication.Secret` behaviour."
         )}
    end
  end
end
