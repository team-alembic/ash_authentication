defmodule AshAuthentication.Strategy.Password.Verifier do
  @moduledoc """
  DSL verifier for the password strategy.
  """

  alias AshAuthentication.{HashProvider, Sender, Strategy.Password}
  alias Spark.Error.DslError
  import AshAuthentication.Validations

  @doc false
  @spec verify(Password.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, _dsl_state) do
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
