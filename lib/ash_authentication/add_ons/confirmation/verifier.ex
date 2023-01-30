defmodule AshAuthentication.AddOn.Confirmation.Verifier do
  @moduledoc """
  DSL verifier for confirmation add-on.
  """

  alias AshAuthentication.{AddOn.Confirmation, Sender}
  alias Spark.Error.DslError
  import AshAuthentication.Validations

  @doc false
  @spec verify(Confirmation.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, _dsl_state) do
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
