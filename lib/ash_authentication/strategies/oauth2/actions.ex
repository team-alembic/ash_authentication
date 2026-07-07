# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.Actions do
  @moduledoc """
  Actions for the oauth2 strategy.

  Provides the code interface for working with resources via an OAuth2 strategy.
  """

  alias Ash.{
    Changeset,
    Error.Framework.AssumptionFailed,
    Error.Invalid.NoSuchAction,
    Query,
    Resource
  }

  alias AshAuthentication.{
    AddOn.Confirmation,
    Errors,
    Errors.ConfirmationRequired,
    Info,
    Strategy.OAuth2
  }

  @doc """
  Attempt to sign in a user.
  """
  @spec sign_in(OAuth2.t(), map, keyword) :: {:ok, Resource.Record.t()} | {:error, any}
  def sign_in(strategy, _params, _options) when strategy.registration_enabled?,
    do:
      {:error,
       NoSuchAction.exception(
         resource: strategy.resource,
         action: strategy.sign_in_action_name,
         type: :read
       )}

  def sign_in(strategy, params, options) do
    options =
      options
      |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

    strategy.resource
    |> Query.new()
    |> Query.set_context(%{
      private: %{
        ash_authentication?: true
      }
    })
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

      {:error, error} when is_struct(error, Errors.AuthenticationFailed) ->
        {:error, error}

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
  Attempt to register a new user.
  """
  @spec register(OAuth2.t(), map, keyword) :: {:ok, Resource.Record.t()} | {:error, any}
  def register(strategy, params, options) when strategy.registration_enabled? do
    action = Resource.Info.action(strategy.resource, strategy.register_action_name, :create)

    options =
      options
      |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

    strategy.resource
    |> Changeset.new()
    |> Changeset.set_context(%{
      private: %{
        ash_authentication?: true
      }
    })
    |> Changeset.for_create(
      strategy.register_action_name,
      params,
      Keyword.merge(options,
        upsert?: true,
        upsert_identity: action.upsert_identity
      )
    )
    |> Ash.create()
    |> case do
      {:error, error} ->
        case find_confirmation_required(error) do
          {:ok, confirmation_required} ->
            {:error, confirmation_required(strategy, confirmation_required, options)}

          :error ->
            {:error,
             Errors.AuthenticationFailed.exception(
               strategy: strategy,
               caused_by: error
             )}
        end

      other ->
        other
    end
  end

  def register(%OAuth2{} = strategy, _params, _options),
    do:
      {:error,
       NoSuchAction.exception(
         resource: strategy.resource,
         action: strategy.register_action_name,
         type: :create
       )}

  # `on_untrusted_email_match :confirm`: issue a confirmation to the existing
  # account's email, then surface a generic `AuthenticationFailed` carrying a
  # scrubbed `ConfirmationRequired` as its reason. The plug/controller can match
  # on that reason to tell the user to check their email, without the user
  # record or provider tokens riding downstream.
  defp confirmation_required(strategy, %ConfirmationRequired{} = confirmation_required, opts) do
    reason =
      case issue_link_confirmation(strategy, confirmation_required, opts) do
        :ok -> ConfirmationRequired.exception(strategy: strategy)
        {:error, reason} -> reason
      end

    Errors.AuthenticationFailed.exception(strategy: strategy, caused_by: reason)
  end

  defp issue_link_confirmation(strategy, %ConfirmationRequired{} = confirmation_required, opts) do
    payload = %{
      "strategy" => to_string(strategy.name),
      "user_info" => confirmation_required.user_info,
      "oauth_tokens" => confirmation_required.oauth_tokens
    }

    with {:ok, confirmation} <- find_confirmation_add_on(strategy.resource),
         {:ok, token} <-
           Confirmation.confirmation_token_for_link(
             confirmation,
             confirmation_required.user,
             payload,
             opts
           ) do
      {sender, send_opts} = confirmation.sender

      send_opts
      |> Keyword.put(:tenant, Keyword.get(opts, :tenant))
      |> Keyword.put(:confirmation_type, :identity_link)
      |> Keyword.put(:provider, strategy.name)
      |> then(&sender.send(confirmation_required.user, token, &1))

      :ok
    end
  end

  defp find_confirmation_add_on(resource) do
    case Enum.find(Info.authentication_add_ons(resource), &match?(%Confirmation{}, &1)) do
      nil ->
        {:error,
         AssumptionFailed.exception(
           message:
             "`on_untrusted_email_match :confirm` requires a confirmation add-on, but none was found"
         )}

      confirmation ->
        {:ok, confirmation}
    end
  end

  defp find_confirmation_required(%ConfirmationRequired{} = error), do: {:ok, error}

  defp find_confirmation_required(%{errors: errors}) when is_list(errors),
    do: find_confirmation_required(errors)

  defp find_confirmation_required(errors) when is_list(errors) do
    Enum.find_value(errors, :error, fn error ->
      case find_confirmation_required(error) do
        {:ok, _} = found -> found
        :error -> false
      end
    end)
  end

  defp find_confirmation_required(_), do: :error
end
