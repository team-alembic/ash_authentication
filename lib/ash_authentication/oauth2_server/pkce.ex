# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.PKCE do
  @moduledoc """
  PKCE (RFC 7636) S256 helpers.

  We only support `S256` — `plain` is rejected at the authorize endpoint per
  OAuth 2.1.
  """

  @doc """
  Compute the S256 code challenge for a verifier.

      challenge = base64url(sha256(verifier))
  """
  @spec challenge(String.t()) :: String.t()
  def challenge(verifier) when is_binary(verifier) do
    :sha256
    |> :crypto.hash(verifier)
    |> Base.url_encode64(padding: false)
  end

  @doc """
  Constant-time comparison of `verifier` against a stored `challenge`.

  Returns `:ok` if they match, `:error` otherwise. Bad input shapes return
  `:error` rather than crashing.
  """
  @spec verify(String.t() | nil, String.t() | nil) :: :ok | :error
  def verify(verifier, challenge) when is_binary(verifier) and is_binary(challenge) do
    if Plug.Crypto.secure_compare(challenge(verifier), challenge),
      do: :ok,
      else: :error
  end

  def verify(_, _), do: :error
end
