# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Otp.SignInPreparation do
  @moduledoc """
  Prepare a query for OTP sign in.

  This preparation:
  1. Filters the query by the identity field.
  2. After the query, computes the deterministic JTI from the submitted OTP code.
  3. Looks up the stored OTP token by JTI.
  4. If found and valid, optionally revokes it (single-use), generates an auth JWT,
     and returns the user with the token in metadata.
  """

  use Ash.Resource.Preparation
  alias Ash.{Query, Resource, Resource.Preparation}
  alias AshAuthentication.{Info, Jwt, Strategy.Otp, TokenResource}
  require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, _opts, context) do
    strategy = Info.strategy_for_action!(query.resource, query.action.name)

    identity_field = strategy.identity_field
    identity = Query.get_argument(query, identity_field)
    otp_code = Query.get_argument(query, strategy.otp_param_name)

    if is_nil(identity) || is_nil(otp_code) do
      Query.do_filter(query, false)
    else
      query
      |> Query.filter(^ref(identity_field) == ^identity)
      |> Query.after_action(&after_action(&1, &2, strategy, otp_code, context))
    end
  end

  defp after_action(_query, [user], strategy, otp_code, context) do
    context_opts = Ash.Context.to_opts(context)
    subject = AshAuthentication.user_to_subject(user)
    normalized_otp = Otp.normalize_otp(strategy, otp_code)
    jti = Otp.compute_deterministic_jti(strategy, subject, normalized_otp)

    token_resource = Info.authentication_tokens_token_resource!(strategy.resource)

    case TokenResource.Actions.get_token(
           token_resource,
           %{"jti" => jti, "purpose" => "otp"},
           context_opts
         ) do
      {:ok, [_ | _]} ->
        # OTP token found - valid
        if strategy.single_use_token? do
          TokenResource.Actions.revoke_jti(token_resource, jti, subject, context_opts)
        end

        {:ok, auth_token, _claims} =
          Jwt.token_for_user(user, %{}, context_opts)

        {:ok, [Resource.put_metadata(user, :token, auth_token)]}

      _ ->
        # No matching token found - invalid OTP
        {:ok, []}
    end
  end

  defp after_action(_query, [], _strategy, _otp_code, _context) do
    {:ok, []}
  end

  defp after_action(_query, _users, _strategy, _otp_code, _context) do
    {:ok, []}
  end
end
