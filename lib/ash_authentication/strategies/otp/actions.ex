# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Otp.Actions do
  @moduledoc """
  Actions for the OTP strategy.

  Provides the code interface for working with user resources for OTP
  authentication.
  """

  alias Ash.{Changeset, Query, Resource}
  alias AshAuthentication.{Errors, Info, Strategy.Otp}

  @doc """
  Request an OTP code for a user.
  """
  @spec request(Otp.t(), map, keyword) :: :ok | {:error, any}
  def request(strategy, params, options) do
    options =
      options
      |> Keyword.put_new_lazy(:domain, fn ->
        Info.domain!(strategy.resource)
      end)

    strategy.resource
    |> Query.new()
    |> Query.set_context(%{private: %{ash_authentication?: true}})
    |> Query.for_read(strategy.request_action_name, params, options)
    |> Ash.read()
    |> case do
      {:ok, _} -> :ok
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Attempt to sign a user in via OTP code.
  """
  @spec sign_in(Otp.t(), map, keyword) ::
          {:ok, Resource.record()} | {:error, Errors.AuthenticationFailed.t()}
  def sign_in(strategy, params, options) do
    if strategy.registration_enabled? do
      sign_in_with_registration(strategy, params, options)
    else
      sign_in_without_registration(strategy, params, options)
    end
  end

  defp sign_in_with_registration(strategy, params, options) do
    strategy.resource
    |> Changeset.new()
    |> Changeset.set_context(%{private: %{ash_authentication?: true}})
    |> Changeset.for_create(strategy.sign_in_action_name, params, options)
    |> Ash.create()
    |> case do
      {:ok, record} ->
        {:ok, record}

      {:error, error} ->
        {:error,
         Errors.AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: error
         )}
    end
  end

  defp sign_in_without_registration(strategy, params, options) do
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
