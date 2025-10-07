# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.LogOutEverywhere.Verifier do
  @moduledoc """
  DSL verifier for the log-out-everywhere add-on.
  """

  alias AshAuthentication.{AddOn.LogOutEverywhere, Info}
  alias Spark.{Dsl.Verifier, Error.DslError}

  @doc false
  @spec verify(LogOutEverywhere.t(), map) :: :ok | {:error, Exception.t()}
  def verify(_strategy, dsl_state) do
    with :ok <- store_all_tokens_enabled(dsl_state) do
      require_token_presence_enabled(dsl_state)
    end
  end

  defp store_all_tokens_enabled(dsl_state) do
    if Info.authentication_tokens_store_all_tokens?(dsl_state) do
      :ok
    else
      configuration_error(dsl_state)
    end
  end

  defp require_token_presence_enabled(dsl_state) do
    if Info.authentication_tokens_require_token_presence_for_authentication?(dsl_state) do
      :ok
    else
      configuration_error(dsl_state)
    end
  end

  defp configuration_error(dsl_state) do
    {:error,
     DslError.exception(
       module: Verifier.get_persisted(dsl_state, :module),
       path: [:authentication, :add_ons, :log_out_everywhere],
       message: """
       Configuration error:

       The log-out-everywhere extension requires that the `store_all_tokens?`
       and `require_token_presence_for_authentication?` options be enabled.

       ```
       authentication do
         tokens do
           store_all_tokens? true
           require_token_presence_for_authentication? true
         end
       end
       """
     )}
  end
end
