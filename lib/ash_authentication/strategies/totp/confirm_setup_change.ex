# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.ConfirmSetupChange do
  @moduledoc """
  Confirms a pending TOTP setup by verifying a code and storing the secret.

  This change is used when `confirm_setup_enabled?` is true. It:

  1. Validates the TOTP code format (6 digits)
  2. Verifies the setup_token JWT
  3. Retrieves the pending secret from the token resource
  4. Verifies the TOTP code against the secret
  5. Stores the secret on the user
  6. Revokes the setup token (after successful storage)

  Token revocation is performed after the secret is stored to avoid losing the
  token if storage fails for any reason.

  This ensures the user has correctly saved their TOTP secret before it's activated.
  """
  use Ash.Resource.Change

  alias Ash.Changeset
  alias Ash.Error.Changes.Required
  alias Ash.Error.Framework.AssumptionFailed
  alias AshAuthentication.{Errors.AuthenticationFailed, Info, Jwt, TokenResource}
  alias AshAuthentication.Strategy.Totp.Helpers

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
           :ok <- validate_code_format(code, strategy),
           {:ok, secret} <- verify_token_and_get_secret(setup_token, strategy),
           :ok <- verify_code(secret, code, strategy) do
        changeset
        |> Changeset.force_change_attribute(strategy.secret_field, secret)
        |> Changeset.put_context(:setup_token_to_revoke, setup_token)
      else
        {:error, reason} ->
          Changeset.add_error(changeset, reason)
      end
    end)
    |> Changeset.after_action(fn changeset, result ->
      case changeset.context[:setup_token_to_revoke] do
        nil ->
          {:ok, result}

        setup_token ->
          revoke_token(setup_token, strategy)
          {:ok, result}
      end
    end)
    |> Changeset.after_action(&preserve_authentication_metadata/2)
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

  defp validate_code_format(code, strategy) do
    case Helpers.validate_totp_code(code) do
      :ok -> :ok
      {:error, :invalid_format} -> {:error, invalid_code_format_error(strategy)}
    end
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

      {:error, reason} when is_exception(reason) ->
        {:error, reason}

      {:error, reason} ->
        {:error, invalid_token_error(strategy, "Token verification failed: #{inspect(reason)}")}
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

  defp invalid_code_format_error(strategy) do
    AuthenticationFailed.exception(
      strategy: strategy,
      caused_by: %{
        module: __MODULE__,
        strategy: strategy,
        action: :confirm_setup,
        message: "Invalid TOTP code format"
      }
    )
  end

  # Keys that should be preserved from the input user to the result
  @preserved_metadata_keys [:token, :authentication_strategies, :totp_verified_at]

  defp preserve_authentication_metadata(changeset, result) do
    original_metadata = changeset.data.__metadata__ || %{}

    result =
      @preserved_metadata_keys
      |> Enum.reduce(result, fn key, acc ->
        case Map.get(original_metadata, key) do
          nil -> acc
          value -> Ash.Resource.put_metadata(acc, key, value)
        end
      end)

    {:ok, result}
  end
end
