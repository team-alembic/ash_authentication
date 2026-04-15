# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Otp.SignInHelpers do
  @moduledoc false

  alias AshAuthentication.TokenResource
  alias AshAuthentication.TokenResource.Info, as: TokenInfo

  @doc """
  Fetch a stored OTP token by JTI while holding a `SELECT FOR UPDATE` row lock.

  Both sign-in paths (the read-backed preparation and the create-backed change)
  use this to serialize concurrent sign-in attempts for the same OTP code. The
  caller is expected to invoke this inside a transaction.
  """
  @spec get_otp_token_locked(module, String.t(), keyword) ::
          {:ok, [Ash.Resource.record()]} | {:error, any}
  def get_otp_token_locked(token_resource, jti, context_opts) do
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

  @doc """
  Consume an OTP token that has been located via `get_otp_token_locked/3`.

  Returns `:ok` if the token was unrevoked (and has now been revoked), or if
  the strategy is not using single-use tokens. Returns
  `{:error, :already_consumed}` if a revocation record already exists — which
  means another concurrent request won the race after the row lock was released.
  """
  @spec consume_token(struct, module, String.t(), String.t(), keyword) ::
          :ok | {:error, :already_consumed}
  def consume_token(%{single_use_token?: false}, _token_resource, _jti, _subject, _context_opts),
    do: :ok

  def consume_token(_strategy, token_resource, jti, subject, context_opts) do
    if TokenResource.Actions.jti_revoked?(token_resource, jti, context_opts) do
      {:error, :already_consumed}
    else
      TokenResource.Actions.revoke_jti(token_resource, jti, subject, context_opts)
      :ok
    end
  end
end
