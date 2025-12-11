# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.ConfirmSetupChange do
  @moduledoc """
  Confirms a pending TOTP setup by verifying a code and storing the secret.

  This change is used when `confirm_setup_enabled?` is true. It:

  1. Verifies the setup_token JWT
  2. Retrieves the pending secret from the token resource
  3. Verifies the TOTP code against the secret
  4. Revokes the setup token
  5. Stores the secret on the user

  This ensures the user has correctly saved their TOTP secret before it's activated.
  """
  use Ash.Resource.Change

  alias Ash.Changeset
  alias Ash.Error.Changes.Required
  alias Ash.Error.Framework.AssumptionFailed
  alias AshAuthentication.{Errors.AuthenticationFailed, Info, Jwt, TokenResource}

  @doc false
  @impl true
  def change(changeset, _context, _opts) do
    case Info.strategy_for_action(changeset.resource, changeset.action.name) do
      {:ok, strategy} ->
        do_change(changeset, strategy)

      :error ->
        raise AssumptionFailed,
          message: "Action does not correlate with an authentication strategy"
    end
  end

  defp do_change(changeset, strategy) do
    changeset
    |> Changeset.set_context(%{private: %{ash_authentication?: true}})
    |> Changeset.before_action(fn changeset ->
      with {:ok, setup_token} <- get_argument(changeset, :setup_token),
           {:ok, code} <- get_argument(changeset, :code),
           {:ok, secret} <- verify_token_and_get_secret(setup_token, strategy),
           :ok <- verify_code(secret, code, strategy),
           :ok <- revoke_token(setup_token, strategy) do
        Changeset.force_change_attribute(changeset, strategy.secret_field, secret)
      else
        {:error, reason} ->
          Changeset.add_error(changeset, reason)
      end
    end)
  end

  defp get_argument(changeset, name) do
    case Changeset.get_argument(changeset, name) do
      nil -> {:error, missing_argument_error(changeset, name)}
      value -> {:ok, value}
    end
  end

  defp missing_argument_error(changeset, argument) do
    Required.exception(
      resource: changeset.resource,
      field: argument,
      type: :argument
    )
  end

  defp verify_token_and_get_secret(setup_token, strategy) do
    with {:ok, %{"jti" => jti}, _resource} <- Jwt.verify(setup_token, strategy.resource),
         {:ok, token_resource} <- Info.authentication_tokens_token_resource(strategy.resource),
         {:ok, [token_record]} <-
           TokenResource.Actions.get_token(
             token_resource,
             %{"jti" => jti, "purpose" => "totp_setup"},
             []
           ),
         {:ok, encoded_secret} <- get_extra_data_secret(token_record) do
      case Base.decode64(encoded_secret) do
        {:ok, secret} -> {:ok, secret}
        :error -> {:error, invalid_token_error(strategy, "Invalid secret encoding")}
      end
    else
      {:ok, []} ->
        {:error, invalid_token_error(strategy, "Setup token not found or expired")}

      {:ok, _tokens} ->
        {:error, invalid_token_error(strategy, "Ambiguous setup token")}

      :error ->
        {:error, invalid_token_error(strategy, "Invalid setup token")}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp get_extra_data_secret(token_record) do
    case token_record.extra_data do
      %{"secret" => secret} when is_binary(secret) -> {:ok, secret}
      _ -> {:error, :missing_secret}
    end
  end

  defp verify_code(secret, code, strategy) do
    if NimbleTOTP.valid?(secret, code, period: strategy.period) do
      :ok
    else
      {:error, invalid_code_error(strategy)}
    end
  end

  defp revoke_token(setup_token, strategy) do
    with {:ok, token_resource} <- Info.authentication_tokens_token_resource(strategy.resource) do
      TokenResource.Actions.revoke(token_resource, setup_token, [])
    end
  end

  defp invalid_token_error(strategy, message) do
    AuthenticationFailed.exception(
      strategy: strategy,
      caused_by: %{
        module: __MODULE__,
        strategy: strategy,
        action: :confirm_setup,
        message: message
      }
    )
  end

  defp invalid_code_error(strategy) do
    AuthenticationFailed.exception(
      strategy: strategy,
      caused_by: %{
        module: __MODULE__,
        strategy: strategy,
        action: :confirm_setup,
        message: "Invalid TOTP code"
      }
    )
  end
end
