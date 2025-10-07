# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.ApiKey.Actions do
  @moduledoc """
  Actions for the API key strategy.

  Provides the code interface for working with user resources for providing
  API keys resurce.
  """

  alias Ash.{Query, Resource}
  alias AshAuthentication.{Errors, Info, Strategy.ApiKey}

  @doc """
  Attempt to sign a user in via API key.
  """
  @spec sign_in(ApiKey.t(), map, keyword) ::
          {:ok, Resource.record()} | {:error, Errors.AuthenticationFailed.t()}
  def sign_in(strategy, params, options) do
    options =
      options
      |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

    strategy.resource
    |> Query.new()
    |> Query.set_context(%{private: %{ash_authentication?: true}})
    |> Query.for_read(strategy.sign_in_action_name, params, options)
    |> Ash.read()
    |> case do
      {:ok, [user]} ->
        {:ok, user}

      {:ok, []} ->
        {:error,
         Errors.AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :sign_in,
             message: "Query returned no users"
           }
         )}

      {:ok, _users} ->
        {:error,
         Errors.AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :sign_in,
             message: "Query returned too many users"
           }
         )}

      {:error, error} when is_exception(error) ->
        {:error,
         Errors.AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: error
         )}

      {:error, error} ->
        {:error,
         Errors.AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :sign_in,
             message: "Query returned error: #{inspect(error)}"
           }
         )}
    end
  end
end
