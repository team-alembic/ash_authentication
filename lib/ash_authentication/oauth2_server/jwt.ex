# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.Jwt do
  @moduledoc """
  Mint and verify OAuth 2.1 access tokens.

  Uses HS256 with a shared secret resolved through the
  `AshAuthentication.Secret` behaviour.

  ## Why this exists alongside `AshAuthentication.Jwt`

  Both modules wrap Joken. They are kept separate because:

    * **Audience binding (RFC 8707)** — every minted token carries an `aud`
      matching the configured `resource_url`, and `verify/2` rejects tokens
      whose `aud` doesn't match. `AshAuthentication.Jwt`'s `aud` is
      hardcoded to a version constraint and is not customizable per-token.
    * **Hot-path verify** — the resource server validates a token on every
      protected request. Verify here is signature + claims only, no user
      load. The bearer plug controls when the user record is fetched.
    * **Decoupling** — these tokens identify a user by their primary key
      (`sub`), not via an AshAuthentication strategy, so we don't require
      the user resource to declare `authentication.tokens.enabled? true`.
  """

  @signer_alg "HS256"

  @doc """
  Mint a new access token.

  Required keys: `:sub`, `:client_id`, `:scope`.
  Optional: `:ttl` (seconds, defaults to the server's `access_token_lifetime`).
  """
  @spec mint(server :: module(), keyword()) ::
          {:ok, String.t(), map()} | {:error, term()}
  def mint(server, opts) do
    sub = Keyword.fetch!(opts, :sub)
    client_id = Keyword.fetch!(opts, :client_id)
    scope = Keyword.fetch!(opts, :scope)
    ttl = Keyword.get(opts, :ttl, server.access_token_lifetime())
    now = System.system_time(:second)

    claims = %{
      "iss" => server.issuer_url(),
      "sub" => to_string(sub),
      "aud" => server.resource_url(),
      "client_id" => to_string(client_id),
      "scope" => scope,
      "iat" => now,
      "nbf" => now,
      "exp" => now + ttl,
      "jti" => generate_jti()
    }

    signer = Joken.Signer.create(@signer_alg, server.signing_secret())

    case Joken.encode_and_sign(claims, signer) do
      {:ok, token, _} -> {:ok, token, claims}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc """
  Verify a token's signature, issuer, audience, and expiry.

  Returns `{:ok, claims}` on success or `{:error, reason}` on failure.
  """
  @spec verify(server :: module(), String.t()) :: {:ok, map()} | {:error, term()}
  def verify(server, token) when is_binary(token) do
    signer = Joken.Signer.create(@signer_alg, server.signing_secret())

    with {:ok, claims} <- Joken.verify(token, signer),
         :ok <- check_iss(claims, server),
         :ok <- check_aud(claims, server),
         :ok <- check_exp(claims) do
      {:ok, claims}
    end
  end

  def verify(_, _), do: {:error, :invalid_token}

  defp check_iss(%{"iss" => iss}, server) do
    if iss == server.issuer_url(), do: :ok, else: {:error, :invalid_issuer}
  end

  defp check_iss(_, _), do: {:error, :invalid_issuer}

  defp check_aud(%{"aud" => aud}, server) do
    expected = server.resource_url()

    cond do
      aud == expected -> :ok
      is_list(aud) and expected in aud -> :ok
      true -> {:error, :invalid_audience}
    end
  end

  defp check_aud(_, _), do: {:error, :invalid_audience}

  defp check_exp(%{"exp" => exp}) when is_integer(exp) do
    if System.system_time(:second) < exp, do: :ok, else: {:error, :expired}
  end

  defp check_exp(_), do: {:error, :missing_exp}

  defp generate_jti do
    if Code.ensure_loaded?(Ash.UUIDv7) and function_exported?(Ash.UUIDv7, :generate, 0) do
      Ash.UUIDv7.generate()
    else
      Ash.UUID.generate()
    end
  end
end
