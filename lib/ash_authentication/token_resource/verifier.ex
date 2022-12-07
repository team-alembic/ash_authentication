defmodule AshAuthentication.TokenResource.Verifier do
  @moduledoc """
  The token resource verifier.
  """

  use Spark.Dsl.Transformer
  require Ash.Expr
  alias Spark.{Dsl.Transformer, Error.DslError}

  @doc false
  @impl true
  @spec after?(any) :: boolean()
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
    validate_api_presence(dsl_state)
  end

  defp validate_api_presence(dsl_state) do
    with api when not is_nil(api) <- Transformer.get_option(dsl_state, [:token], :api),
         true <- function_exported?(api, :spark_is, 0),
         Ash.Api <- api.spark_is() do
      {:ok, api}
    else
      nil ->
        {:error,
         DslError.exception(
           path: [:token, :api],
           message: "An API module must be present"
         )}

      _ ->
        {:error,
         DslError.exception(
           path: [:token, :api],
           message: "Module is not an Ash.Api."
         )}
    end
  end
end
