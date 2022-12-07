defmodule AshAuthentication.Strategy.Password.Verifier do
  @moduledoc """
  DSL verifier for the password strategy.
  """

  use Spark.Dsl.Transformer
  alias AshAuthentication.{HashProvider, Info, Sender, Strategy.Password}
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
    |> Stream.filter(&is_struct(&1, Password))
    |> Enum.reduce_while(:ok, fn strategy, :ok ->
      case transform_strategy(strategy) do
        :ok -> {:cont, :ok}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  def transform_strategy(strategy) do
    with :ok <- validate_behaviour(strategy.hash_provider, HashProvider) do
      maybe_validate_resettable_sender(strategy)
    end
  end

  defp maybe_validate_resettable_sender(%{resettable: [resettable]}) do
    with {:ok, {sender, _opts}} <- Map.fetch(resettable, :sender),
         :ok <- validate_behaviour(sender, Sender) do
      :ok
    else
      :error ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, :password, :resettable],
           message: "A `sender` is required."
         )}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp maybe_validate_resettable_sender(_), do: :ok
end
