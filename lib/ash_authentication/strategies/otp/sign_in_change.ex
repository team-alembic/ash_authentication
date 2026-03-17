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
      verify_and_apply(changeset, strategy, identity, otp_code, context)
    end
  end

  defp verify_and_apply(changeset, strategy, identity, otp_code, context) do
    normalized_otp = Otp.normalize_otp(strategy, otp_code)

    jti =
      Otp.compute_deterministic_jti_for_identity(strategy, to_string(identity), normalized_otp)

    token_resource = Info.authentication_tokens_token_resource!(strategy.resource)
    context_opts = Ash.Context.to_opts(context)

    case TokenResource.Actions.get_token(
           token_resource,
           %{"jti" => jti, "purpose" => "otp"},
           context_opts
         ) do
      {:ok, [_ | _]} ->
        changeset
        |> Changeset.force_change_attribute(strategy.identity_field, identity)
        |> Changeset.after_transaction(
          &after_transaction(&1, &2, strategy, token_resource, jti, context_opts)
        )

      _ ->
        add_otp_error(changeset, strategy, "Invalid or expired OTP code")
    end
  end

  defp after_transaction(_changeset, {:ok, record}, strategy, token_resource, jti, context_opts) do
    if strategy.single_use_token? do
      subject = AshAuthentication.user_to_subject(record)
      TokenResource.Actions.revoke_jti(token_resource, jti, subject, context_opts)
    end

    {:ok, auth_token, _claims} = Jwt.token_for_user(record, %{}, context_opts)
    {:ok, Resource.put_metadata(record, :token, auth_token)}
  end

  defp after_transaction(
         _changeset,
         {:error, error},
         _strategy,
         _token_resource,
         _jti,
         _context_opts
       ) do
    {:error, error}
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
