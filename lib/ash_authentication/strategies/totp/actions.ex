# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.Actions do
  @moduledoc """
  Actions for the TOTP strategy.

  Provides the code interface for TOTP setup, sign-in, and verification.
  """

  alias Ash.{ActionInput, Changeset, Query, Resource}
  alias Ash.Error.Changes.Required
  alias Ash.Error.Invalid
  alias AshAuthentication.{Errors, Info, Strategy.Totp}

  @doc """
  Set up TOTP for a user by generating a new secret.

  Takes a user record and runs the setup action which generates a new TOTP
  secret. The user can then retrieve the `totp_url` calculation to display
  a QR code for scanning with an authenticator app.
  """
  @spec setup(Totp.t(), map, keyword) :: {:ok, Resource.record()} | {:error, any}
  def setup(strategy, params, options) do
    user = Map.get(params, :user) || Map.get(params, "user")

    case user do
      nil ->
        {:error,
         Invalid.exception(
           errors: [
             Required.exception(
               resource: strategy.resource,
               field: :user,
               type: :argument
             )
           ]
         )}

      user ->
        options =
          options
          |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

        user
        |> Changeset.new()
        |> Changeset.set_context(%{private: %{ash_authentication?: true}})
        |> Changeset.for_update(strategy.setup_action_name, %{}, options)
        |> Ash.update()
        |> case do
          {:ok, user} ->
            {:ok, user}

          {:error, error} ->
            {:error,
             Errors.AuthenticationFailed.exception(
               strategy: strategy,
               caused_by: error
             )}
        end
    end
  end

  @doc """
  Confirm TOTP setup by verifying a code and activating the secret.

  Used when `confirm_setup_enabled?` is true. Takes a user, setup_token, and
  TOTP code. If the code is valid, the secret is stored on the user and the
  setup token is revoked.
  """
  @spec confirm_setup(Totp.t(), map, keyword) :: {:ok, Resource.record()} | {:error, any}
  def confirm_setup(strategy, params, options) do
    user = Map.get(params, :user) || Map.get(params, "user")

    case user do
      nil ->
        {:error,
         Invalid.exception(
           errors: [
             Required.exception(
               resource: strategy.resource,
               field: :user,
               type: :argument
             )
           ]
         )}

      user ->
        options =
          options
          |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

        # Remove user from params since it's the changeset target, not an action argument
        action_params =
          params
          |> Map.delete(:user)
          |> Map.delete("user")

        user
        |> Changeset.new()
        |> Changeset.set_context(%{private: %{ash_authentication?: true}})
        |> Changeset.for_update(strategy.confirm_setup_action_name, action_params, options)
        |> Ash.update()
        |> case do
          {:ok, user} ->
            {:ok, user}

          {:error, error} ->
            {:error,
             Errors.AuthenticationFailed.exception(
               strategy: strategy,
               caused_by: error
             )}
        end
    end
  end

  @doc """
  Sign in using a TOTP code.

  Takes an identity (e.g., email) and a TOTP code, and returns the user if
  the code is valid.
  """
  @spec sign_in(Totp.t(), map, keyword) :: {:ok, Resource.record()} | {:error, any}
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

  @doc """
  Verify a TOTP code for a user.

  Takes a user and a TOTP code, and returns `{:ok, true}` if the code is valid
  or `{:ok, false}` if it is not.
  """
  @spec verify(Totp.t(), map, keyword) :: {:ok, boolean} | {:error, any}
  def verify(strategy, params, options) do
    options =
      options
      |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

    strategy.resource
    |> ActionInput.new()
    |> ActionInput.set_context(%{private: %{ash_authentication?: true}})
    |> ActionInput.for_action(strategy.verify_action_name, params, options)
    |> Ash.run_action()
    |> case do
      {:ok, result} ->
        {:ok, result}

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
             action: :verify,
             message: "Action returned error: #{inspect(error)}"
           }
         )}
    end
  end
end
