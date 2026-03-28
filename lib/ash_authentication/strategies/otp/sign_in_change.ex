# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Otp.SignInChange do
  @moduledoc """
  Change for OTP sign-in when registration is enabled.

  Used on a create action with upsert to allow new users to register
  via OTP. Validates the OTP code, sets the identity attribute, and
  generates an auth JWT on success.
  """

  use Ash.Resource.Change
  alias Ash.{Changeset, Resource, Resource.Change}
  alias AshAuthentication.{Errors.InvalidToken, Info, Jwt, Strategy.Otp, TokenResource}
  alias AshAuthentication.TokenResource.Info, as: TokenInfo

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.Context.t()) :: Changeset.t()
  def change(changeset, opts, context) do
    case Info.find_strategy(changeset, context, opts) do
      {:ok, strategy} ->
        apply_otp_change(changeset, strategy, context)

      _ ->
        Changeset.add_error(
          changeset,
          "No strategy found for action #{inspect(changeset.resource)}.#{changeset.action.name}"
        )
    end
  end

  defp apply_otp_change(changeset, strategy, context) do
    identity = Changeset.get_argument(changeset, strategy.identity_field)
    otp_code = Changeset.get_argument(changeset, strategy.otp_param_name)

    if is_nil(identity) || is_nil(otp_code) do
      add_otp_error(changeset, strategy, "Identity and OTP code are required")
    else
      normalized_otp = Otp.normalize_otp(strategy, otp_code)

      jti =
        Otp.compute_deterministic_jti_for_identity(strategy, to_string(identity), normalized_otp)

      token_resource = Info.authentication_tokens_token_resource!(strategy.resource)
      context_opts = Ash.Context.to_opts(context)

      changeset
      |> Changeset.force_change_attribute(strategy.identity_field, identity)
      |> Changeset.after_action(
        &verify_token_and_finalize(&1, &2, strategy, token_resource, jti, context_opts)
      )
    end
  end

  # Runs inside the create/upsert transaction. Locks the token row with
  # SELECT FOR UPDATE so concurrent sign-in attempts for the same OTP code
  # serialize here rather than both succeeding.
  defp verify_token_and_finalize(_changeset, record, strategy, token_resource, jti, context_opts) do
    case get_otp_token_locked(token_resource, jti, context_opts) do
      {:ok, [_ | _]} ->
        with :ok <- maybe_consume_token(strategy, token_resource, jti, record, context_opts) do
          {:ok, auth_token, _claims} = Jwt.token_for_user(record, %{}, context_opts)
          {:ok, Resource.put_metadata(record, :token, auth_token)}
        end

      _ ->
        {:error, otp_error(strategy)}
    end
  end

  defp maybe_consume_token(%{single_use_token?: false}, _, _, _, _), do: :ok

  defp maybe_consume_token(strategy, token_resource, jti, record, context_opts) do
    if TokenResource.Actions.jti_revoked?(token_resource, jti, context_opts) do
      {:error, otp_error(strategy)}
    else
      subject = AshAuthentication.user_to_subject(record)
      TokenResource.Actions.revoke_jti(token_resource, jti, subject, context_opts)
      :ok
    end
  end

  defp get_otp_token_locked(token_resource, jti, context_opts) do
    with {:ok, domain} <- TokenInfo.token_domain(token_resource),
         {:ok, get_token_action_name} <- TokenInfo.token_get_token_action_name(token_resource) do
      token_resource
      |> Ash.Query.new()
      |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
      |> Ash.Query.lock(:for_update)
      |> Ash.Query.for_read(
        get_token_action_name,
        %{"jti" => jti, "purpose" => "otp"},
        Keyword.take(
          Keyword.put(context_opts, :domain, domain),
          [:actor, :authorize?, :tenant, :tracer, :domain]
        )
      )
      |> Ash.read()
    end
  end

  defp otp_error(strategy) do
    InvalidToken.exception(
      field: strategy.otp_param_name,
      reason: "Invalid or expired OTP code",
      type: :otp
    )
  end

  defp add_otp_error(changeset, strategy, reason) do
    Changeset.add_error(
      changeset,
      InvalidToken.exception(
        field: strategy.otp_param_name,
        reason: reason,
        type: :otp
      )
    )
  end
end
