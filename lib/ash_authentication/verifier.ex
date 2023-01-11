defmodule AshAuthentication.Verifier do
  @moduledoc """
  The Authentication verifier.
  """

  use Spark.Dsl.Transformer
  alias AshAuthentication.Info
  alias Spark.{Dsl.Transformer, Error.DslError}
  import AshAuthentication.Utils

  @doc false
  @impl true
  @spec after?(any) :: boolean
  def after?(_), do: true

  @doc false
  @impl true
  @spec before?(any) :: boolean
  def before?(_), do: false

  @doc false
  @impl true
  @spec after_compile? :: boolean
  def after_compile?, do: true

  @doc false
  @impl true
  @spec transform(map) ::
          :ok | {:ok, map} | {:error, term} | {:warn, map, String.t() | [String.t()]} | :halt
  def transform(dsl_state) do
    with {:ok, _api} <- validate_api_presence(dsl_state) do
      validate_token_resource(dsl_state)
    end
  end

  defp validate_api_presence(dsl_state) do
    with api when not is_nil(api) <- Transformer.get_option(dsl_state, [:authentication], :api),
         :ok <- assert_is_module(api),
         true <- function_exported?(api, :spark_is, 0),
         Ash.Api <- api.spark_is() do
      {:ok, api}
    else
      nil ->
        {:error,
         DslError.exception(
           path: [:authentication, :api],
           message: "An API module must be present"
         )}

      _ ->
        {:error,
         DslError.exception(
           path: [:authentication, :api],
           message: "Module is not an Ash.Api."
         )}
    end
  end

  defp validate_token_resource(dsl_state) do
    if_tokens_enabled(dsl_state, fn dsl_state ->
      with {:ok, resource} when is_truthy(resource) <-
             Info.authentication_tokens_token_resource(dsl_state),
           true <- is_atom(resource) do
        :ok
      else
        {:ok, falsy} when is_falsy(falsy) ->
          :ok

        {:error, reason} ->
          {:error, reason}

        false ->
          {:error,
           DslError.exception(
             path: [:authentication, :tokens, :token_resource],
             message: "is not a valid module name"
           )}
      end
    end)
  end

  defp if_tokens_enabled(dsl_state, validator) when is_function(validator, 1) do
    if Info.authentication_tokens_enabled?(dsl_state) do
      validator.(dsl_state)
    else
      :ok
    end
  end
end
