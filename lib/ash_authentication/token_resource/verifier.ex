defmodule AshAuthentication.TokenResource.Verifier do
  @moduledoc """
  The token resource verifier.
  """

  use Spark.Dsl.Transformer
  require Ash.Expr
  alias Spark.{Dsl.Transformer, Error.DslError}
  import AshAuthentication.Utils

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
    validate_domain_presence(dsl_state)
  end

  defp validate_domain_presence(dsl_state) do
    with domain when not is_nil(domain) <- Transformer.get_option(dsl_state, [:token], :domain),
         :ok <- assert_is_module(domain),
         true <- function_exported?(domain, :spark_is, 0),
         Ash.Domain <- domain.spark_is() do
      {:ok, domain}
    else
      nil ->
        {:error,
         DslError.exception(
           path: [:token, :domain],
           message: "A domain module must be present"
         )}

      _ ->
        {:error,
         DslError.exception(
           path: [:token, :domain],
           message: "Module is not an `Ash.Domain`."
         )}
    end
  end
end
