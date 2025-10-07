# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.Confirmation.Verifier do
  @moduledoc """
  DSL verifier for confirmation add-on.
  """

  alias AshAuthentication.{AddOn.Confirmation, Sender}
  alias Spark.{Dsl.Verifier, Error.DslError}
  import AshAuthentication.Validations

  @doc false
  @spec verify(Confirmation.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl_state) do
    case Map.fetch(strategy, :sender) do
      {:ok, {sender, _opts}} ->
        validate_behaviour(sender, Sender)

      :error ->
        {:error,
         DslError.exception(
           module: Verifier.get_persisted(dsl_state, :module),
           path: [:authentication, :add_ons, :confirmation],
           message: "Configuration error"
         )}
    end
  end
end
