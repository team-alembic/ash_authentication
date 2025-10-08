# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.RememberMe.Verifier do
  @moduledoc """
  DSL verifier for the remember me strategy.
  """

  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.RememberMe
  alias Spark.{Dsl.Verifier, Error.DslError}

  @doc false
  @spec verify(RememberMe.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl_state) do
    validate_tokens_enabled(dsl_state, strategy)
  end

  defp validate_tokens_enabled(dsl_state, strategy) do
    resource = Verifier.get_persisted(dsl_state, :module)

    if Info.authentication_tokens_enabled?(dsl_state) do
      :ok
    else
      {:error,
       DslError.exception(
         module: resource,
         path: [
           :authentication,
           :strategies,
           :remember_me,
           strategy.name
         ],
         message: """
         The remmber me strategy requires that tokens are enabled for your resource. For example:

             authentication do
             ...

             tokens do
                 enabled? true
             end
             end
         """
       )}
    end
  end
end
