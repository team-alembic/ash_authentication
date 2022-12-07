defmodule AshAuthentication.AddOn.Confirmation.Verifier do
  @moduledoc """
  DSL verifier for confirmation add-on.
  """

  use Spark.Dsl.Transformer
  alias AshAuthentication.{AddOn.Confirmation, Info, Sender}
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
    |> Info.authentication_add_ons()
    |> Stream.filter(&is_struct(&1, Confirmation))
    |> Enum.reduce_while(:ok, fn strategy, :ok ->
      case transform_strategy(strategy) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp transform_strategy(strategy) do
    case Map.fetch(strategy, :sender) do
      {:ok, {sender, _opts}} ->
        validate_behaviour(sender, Sender)

      :error ->
        {:error,
         DslError.exception(
           path: [:authentication, :add_ons, :confirmation],
           message: "Configuration error"
         )}
    end
  end
end
