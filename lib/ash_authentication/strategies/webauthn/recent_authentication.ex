# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.RecentAuthentication do
  @moduledoc """
  Gatekeeping for adding a passkey to an existing account.

  Enrolling a passkey grants a durable way into the account, so whoever can
  reach `add_credential` with a stolen or long-lived session could leave
  themselves a permanent key. The strategy's `add_credential_enabled?` turns
  the flow off entirely, and `add_credential_max_authentication_age`
  requires the actor to have authenticated recently.

  ## What counts as authenticating

  The most recent of:

  - `opts[:authenticated_at]`: supplied by the caller, as a `DateTime`. The
    plugs pass the issue time of a bearer token the request carries, and
    applications driving `Actions.add_credential/3` directly can pass
    whatever their own session knows.
  - the actor's `:webauthn_verified_at` and `:totp_verified_at` metadata:
    a second-factor verification is a fresh proof of possession.
  - the `iat` (issued-at) claim of the actor's `:token` metadata: the token
    issued when the user signed in, which `AshAuthentication.Plug.Helpers`
    restores from the session.

  An actor with none of these is treated as not recently authenticated.
  """

  alias AshAuthentication.{Errors.AuthenticationFailed, Jwt, Strategy.WebAuthn, Utils}

  @doc """
  Check that `actor` may add a passkey through `strategy` right now.
  """
  @spec check(WebAuthn.t(), Ash.Resource.Record.t(), keyword) :: :ok | {:error, Exception.t()}
  def check(%{add_credential_enabled?: false} = strategy, _actor, _opts),
    do: {:error, failure(strategy, "Adding a passkey is disabled for this strategy")}

  def check(%{add_credential_max_authentication_age: nil}, _actor, _opts), do: :ok

  def check(strategy, actor, opts) do
    max_age = Utils.lifetime_to_seconds(strategy.add_credential_max_authentication_age)

    case authenticated_at(actor, opts) do
      %DateTime{} = at ->
        if DateTime.diff(DateTime.utc_now(), at, :second) <= max_age do
          :ok
        else
          {:error, failure(strategy, "A recent authentication is required to add a passkey")}
        end

      nil ->
        {:error, failure(strategy, "A recent authentication is required to add a passkey")}
    end
  end

  @doc """
  When `actor` last authenticated, as far as the request can tell, or `nil`.
  """
  @spec authenticated_at(Ash.Resource.Record.t(), keyword) :: DateTime.t() | nil
  def authenticated_at(actor, opts \\ []) do
    metadata = Map.get(actor, :__metadata__) || %{}

    [
      Keyword.get(opts, :authenticated_at),
      Map.get(metadata, :webauthn_verified_at),
      Map.get(metadata, :totp_verified_at),
      token_issued_at(Map.get(metadata, :token))
    ]
    |> Enum.map(&to_datetime/1)
    |> Enum.reject(&is_nil/1)
    |> Enum.max(DateTime, fn -> nil end)
  end

  @doc """
  The issue time of `token`, when it is a JWT whose subject is `actor`.
  """
  @spec token_issued_at(String.t() | nil, Ash.Resource.Record.t() | nil) :: DateTime.t() | nil
  def token_issued_at(token, actor \\ nil)

  def token_issued_at(token, actor) when is_binary(token) do
    with {:ok, %{"iat" => iat} = claims} when is_integer(iat) <- Jwt.peek(token),
         true <- is_nil(actor) or claims["sub"] == AshAuthentication.user_to_subject(actor),
         {:ok, at} <- DateTime.from_unix(iat) do
      at
    else
      _ -> nil
    end
  end

  def token_issued_at(_token, _actor), do: nil

  # Session metadata survives as whatever was stored (a `DateTime`), while
  # values that went through JSON (e.g. JWT claims) arrive as ISO 8601.
  defp to_datetime(%DateTime{} = at), do: at

  defp to_datetime(at) when is_binary(at) do
    case DateTime.from_iso8601(at) do
      {:ok, at, _offset} -> at
      _ -> nil
    end
  end

  defp to_datetime(_), do: nil

  defp failure(strategy, message) do
    AuthenticationFailed.exception(
      strategy: strategy,
      caused_by: %{
        module: __MODULE__,
        strategy: strategy,
        action: :add_credential,
        message: message
      }
    )
  end
end
