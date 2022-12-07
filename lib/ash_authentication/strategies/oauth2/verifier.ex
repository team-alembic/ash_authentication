defmodule AshAuthentication.Strategy.OAuth2.Verifier do
  @moduledoc """
  DSL verifier for oauth2 strategies.
  """

  use Spark.Dsl.Transformer
  alias AshAuthentication.{Info, Strategy.OAuth2}
  alias Spark.Error.DslError
  import AshAuthentication.Validations

  @doc false
  @impl true
  @spec after?(module) :: boolean
  def after?(_), do: true

  @doc false
  @impl true
  @spec before?(module) :: boolean
  def before?(_), do: false

  @doc false
  @impl true
  @spec after_compile? :: boolean
  def after_compile?, do: true

  @doc false
  @impl true
  @spec transform(map) ::
          :ok
          | {:ok, map()}
          | {:error, term()}
          | {:warn, map(), String.t() | [String.t()]}
          | :halt
  def transform(dsl_state) do
    dsl_state
    |> Info.authentication_strategies()
    |> Stream.filter(&is_struct(&1, OAuth2))
    |> Enum.reduce_while(:ok, fn strategy, :ok ->
      case transform_strategy(strategy) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp transform_strategy(strategy) do
    with :ok <- validate_secret(strategy, :authorize_path),
         :ok <- validate_secret(strategy, :client_id),
         :ok <- validate_secret(strategy, :client_secret),
         :ok <- validate_secret(strategy, :redirect_uri),
         :ok <- validate_secret(strategy, :site),
         :ok <- validate_secret(strategy, :token_path),
         :ok <- validate_secret(strategy, :user_path) do
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
        validate_behaviour(module, AshAuthentication.Secret)

      _ ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, :oauth2],
           message:
             "Expected `#{inspect(option)}` to be either a string or a module which implements the `AshAuthentication.Sender` behaviour."
         )}
    end
  end
end
