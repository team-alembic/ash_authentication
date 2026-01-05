# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.GeneratePendingSetupChange do
  @moduledoc """
  Generates a pending TOTP setup for two-step confirmation.

  This change is used when `confirm_setup_enabled?` is true. Instead of storing
  the secret directly on the user, it:

  1. Generates a new TOTP secret
  2. Creates a setup token containing the secret
  3. Stores the token in the token resource
  4. Returns the setup_token and totp_url in the user's metadata

  The user must then call the confirm_setup action with a valid TOTP code to
  activate the secret.
  """
  use Ash.Resource.Change

  alias Ash.{Changeset, Resource}
  alias Ash.Error.Framework.AssumptionFailed
  alias AshAuthentication.{Info, Jwt, TokenResource}

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
    |> Changeset.after_action(fn _changeset, user ->
      with {:ok, secret, totp_url} <- generate_secret_and_url(user, strategy),
           {:ok, setup_token} <- generate_and_store_setup_token(user, secret, strategy) do
        user =
          user
          |> Resource.put_metadata(:setup_token, setup_token)
          |> Resource.put_metadata(:totp_url, totp_url)

        {:ok, user}
      end
    end)
  end

  defp generate_secret_and_url(user, strategy) do
    secret = NimbleTOTP.secret(strategy.secret_length)
    identity = Map.get(user, strategy.identity_field)

    totp_url =
      NimbleTOTP.otpauth_uri("#{strategy.issuer}:#{identity}", secret,
        issuer: strategy.issuer,
        period: strategy.period
      )

    {:ok, secret, totp_url}
  end

  defp generate_and_store_setup_token(user, secret, strategy) do
    with {:ok, token_resource} <- Info.authentication_tokens_token_resource(strategy.resource),
         {:ok, token, _claims} <-
           Jwt.token_for_user(
             user,
             %{},
             purpose: :totp_setup,
             token_lifetime: strategy.setup_token_lifetime
           ) do
      encoded_secret = Base.encode64(secret)

      case TokenResource.Actions.store_token(
             token_resource,
             %{
               "token" => token,
               "purpose" => "totp_setup",
               "extra_data" => %{"secret" => encoded_secret}
             },
             []
           ) do
        :ok -> {:ok, token}
        {:error, reason} -> {:error, reason}
      end
    end
  end
end
