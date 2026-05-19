# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.Token do
  @moduledoc """
  Protocol-pure logic for the `/oauth/token` endpoint.

  Supports two grant types:

    * `authorization_code` — with PKCE verification, redirect/resource
      binding checks, and one-shot consumption of the code.
    * `refresh_token` — with rotation and reuse detection per OAuth 2.1
      §4.3.1. A second use of an already-rotated refresh token revokes the
      entire descendant chain.

  All functions return tagged tuples; controllers translate them to HTTP.
  """

  require Ash.Query
  require Logger

  alias AshAuthentication.Oauth2Server.{Jwt, PKCE}

  @typedoc "Result of a successful grant — the bundle returned to the client."
  @type token_response :: %{
          access_token: String.t(),
          token_type: String.t(),
          expires_in: pos_integer(),
          refresh_token: String.t(),
          scope: String.t()
        }

  # ── authorization_code grant ───────────────────────────────────────────────

  @doc """
  Exchange an authorization code (with PKCE verifier) for an access + refresh
  token pair. Consumes the code atomically; a second call with the same code
  returns `{:error, :reuse}`.
  """
  @spec exchange_authorization_code(server :: module(), params :: map()) ::
          {:ok, token_response()}
          | {:error, atom()}
  def exchange_authorization_code(server, params) do
    with {:ok, code, client} <- consume_code(server, params),
         :ok <- verify_pkce(code, params),
         :ok <- check_resource_match(server, params, code),
         :ok <- check_redirect_match(params, code),
         {:ok, access_token, _claims} <-
           Jwt.mint(server,
             sub: code.user_id,
             client_id: client.id,
             scope: code.scope
           ),
         {:ok, refresh_token} <- issue_refresh_token(server, client.id, code) do
      touch_client(client)

      {:ok,
       %{
         access_token: access_token,
         token_type: "Bearer",
         expires_in: server.access_token_lifetime(),
         refresh_token: refresh_token,
         scope: code.scope
       }}
    end
  end

  defp consume_code(server, %{"code" => code_id, "client_id" => client_id})
       when is_binary(code_id) and is_binary(client_id) do
    with {:ok, code} <-
           code_or_error(
             Ash.get(server.authorization_code_resource(), code_id, authorize?: false)
           ),
         :ok <- check_client_match(code, client_id),
         :ok <- check_not_consumed(code),
         :ok <- check_not_expired(code),
         {:ok, code} <-
           code
           |> Ash.Changeset.for_update(:consume, %{})
           |> Ash.update(authorize?: false)
           |> code_or_error(),
         {:ok, client} <-
           code_or_error(
             Ash.get(server.client_resource(), code.client_id, authorize?: false)
           ) do
      {:ok, code, client}
    end
  end

  defp consume_code(_, _), do: {:error, :invalid_request}

  defp code_or_error({:ok, _} = ok), do: ok
  defp code_or_error({:error, _}), do: {:error, :invalid_code}

  defp check_client_match(%{client_id: code_client_id}, client_id) do
    if code_client_id == client_id, do: :ok, else: {:error, :client_mismatch}
  end

  defp check_not_consumed(%{consumed_at: nil}), do: :ok
  defp check_not_consumed(_), do: {:error, :reuse}

  defp check_not_expired(%{expires_at: expires_at}) do
    if DateTime.compare(DateTime.utc_now(), expires_at) == :gt,
      do: {:error, :expired},
      else: :ok
  end

  defp verify_pkce(code, %{"code_verifier" => verifier}) when is_binary(verifier) do
    case PKCE.verify(verifier, code.code_challenge) do
      :ok -> :ok
      :error -> {:error, :pkce}
    end
  end

  defp verify_pkce(_, _), do: {:error, :pkce}

  # `resource` is optional per RFC 8707 §2; if present it must match.
  defp check_resource_match(server, params, code) do
    expected = server.resource_url()

    cond do
      code.resource_uri != expected ->
        {:error, :resource_mismatch}

      is_binary(params["resource"]) and params["resource"] != "" ->
        if AshAuthentication.Oauth2Server.__normalize_url__(params["resource"]) == expected,
          do: :ok,
          else: {:error, :resource_mismatch}

      true ->
        :ok
    end
  end

  defp check_redirect_match(%{"redirect_uri" => uri}, %{redirect_uri: code_uri})
       when is_binary(uri) and is_binary(code_uri) do
    if AshAuthentication.Oauth2Server.__normalize_url__(uri) ==
         AshAuthentication.Oauth2Server.__normalize_url__(code_uri),
       do: :ok,
       else: {:error, :redirect_mismatch}
  end

  defp check_redirect_match(_, _), do: {:error, :redirect_mismatch}

  # ── refresh_token grant ───────────────────────────────────────────────────

  @doc """
  Exchange a refresh token for a new access + refresh pair. Implements
  rotation + reuse detection: a second call with an already-rotated token
  returns `{:error, :reuse}` and revokes the descendant chain.
  """
  @spec exchange_refresh_token(server :: module(), params :: map()) ::
          {:ok, token_response()} | {:error, atom()}
  def exchange_refresh_token(server, %{"refresh_token" => raw, "client_id" => client_id} = params)
      when is_binary(raw) do
    hash = hash_refresh(raw)
    resource = Map.get(params, "resource")

    with {:ok, row} <- find_refresh(server, hash),
         :ok <- check_refresh_validity(server, row, client_id, resource),
         {:ok, access_token, new_refresh, _claims} <- rotate(server, row) do
      touch_client_by_id(server, row.client_id)

      {:ok,
       %{
         access_token: access_token,
         token_type: "Bearer",
         expires_in: server.access_token_lifetime(),
         refresh_token: new_refresh,
         scope: row.scope
       }}
    else
      {:error, :reuse} = err ->
        revoke_chain(server, hash)
        err

      other ->
        other
    end
  end

  def exchange_refresh_token(_, _), do: {:error, :invalid_request}

  defp find_refresh(server, hash) do
    server.refresh_token_resource()
    |> Ash.Query.filter(token_hash == ^hash)
    |> Ash.read_one(authorize?: false)
    |> case do
      {:ok, nil} -> {:error, :invalid_refresh}
      {:ok, row} -> {:ok, row}
      _ -> {:error, :invalid_refresh}
    end
  end

  defp check_refresh_validity(server, row, client_id, resource) do
    expected_resource = server.resource_url()

    resource_ok? =
      case resource do
        nil ->
          true

        "" ->
          true

        bin when is_binary(bin) ->
          AshAuthentication.Oauth2Server.__normalize_url__(bin) == expected_resource
      end

    cond do
      row.client_id != client_id -> {:error, :client_mismatch}
      row.resource_uri != expected_resource -> {:error, :resource_mismatch}
      not resource_ok? -> {:error, :resource_mismatch}
      row.revoked_at -> {:error, :revoked}
      row.rotated_to_id -> {:error, :reuse}
      DateTime.compare(DateTime.utc_now(), row.expires_at) == :gt -> {:error, :expired}
      true -> :ok
    end
  end

  # Issue the new row first; if that succeeds, mark the old row rotated to it.
  defp rotate(server, row) do
    {raw, hash} = generate_refresh()
    expires_at = DateTime.add(DateTime.utc_now(), server.refresh_token_lifetime(), :second)

    with {:ok, new_row} <-
           server.refresh_token_resource()
           |> Ash.Changeset.for_create(:issue, %{
             token_hash: hash,
             client_id: row.client_id,
             user_id: row.user_id,
             scope: row.scope,
             resource_uri: row.resource_uri,
             expires_at: expires_at
           })
           |> Ash.create(authorize?: false),
         {:ok, _} <-
           row
           |> Ash.Changeset.for_update(:rotate, %{rotated_to_id: new_row.id})
           |> Ash.update(authorize?: false),
         {:ok, access_token, claims} <-
           Jwt.mint(server,
             sub: row.user_id,
             client_id: row.client_id,
             scope: row.scope
           ) do
      {:ok, access_token, raw, claims}
    end
  end

  # On reuse detection, walk forward through `rotated_to_id` revoking every
  # descendant of the offending token. RFC 6749 §4.3.1.
  defp revoke_chain(server, hash) do
    case find_refresh(server, hash) do
      {:ok, row} ->
        revoke_descendants(server, row)

      _ ->
        Logger.warning(
          "Oauth2Server: refresh-token reuse detected but couldn't load row for chain revocation"
        )

        :ok
    end
  end

  defp revoke_descendants(server, row) do
    case row |> Ash.Changeset.for_update(:revoke, %{}) |> Ash.update(authorize?: false) do
      {:ok, _} ->
        :ok

      {:error, reason} ->
        Logger.warning(
          "Oauth2Server: failed to revoke refresh token #{inspect(row.id)}: #{inspect(reason)}"
        )
    end

    if row.rotated_to_id do
      case Ash.get(server.refresh_token_resource(), row.rotated_to_id, authorize?: false) do
        {:ok, next} -> revoke_descendants(server, next)
        _ -> :ok
      end
    else
      :ok
    end
  end

  # ── refresh issuance helpers ───────────────────────────────────────────────

  defp issue_refresh_token(server, client_id, code) do
    {raw, hash} = generate_refresh()
    expires_at = DateTime.add(DateTime.utc_now(), server.refresh_token_lifetime(), :second)

    server.refresh_token_resource()
    |> Ash.Changeset.for_create(:issue, %{
      token_hash: hash,
      client_id: client_id,
      user_id: code.user_id,
      scope: code.scope,
      resource_uri: code.resource_uri,
      expires_at: expires_at
    })
    |> Ash.create(authorize?: false)
    |> case do
      {:ok, _} -> {:ok, raw}
      {:error, _} -> {:error, :refresh_create_failed}
    end
  end

  defp generate_refresh do
    raw = :crypto.strong_rand_bytes(32) |> Base.url_encode64(padding: false)
    hash = hash_refresh(raw)
    {raw, hash}
  end

  defp hash_refresh(raw),
    do: :crypto.hash(:sha256, raw) |> Base.encode16(case: :lower)

  # ── client touch (best-effort) ────────────────────────────────────────────

  defp touch_client(client) do
    client
    |> Ash.Changeset.for_update(:touch, %{})
    |> Ash.update(authorize?: false)
  rescue
    _ -> :ok
  end

  defp touch_client_by_id(server, client_id) do
    case Ash.get(server.client_resource(), client_id, authorize?: false) do
      {:ok, client} -> touch_client(client)
      _ -> :ok
    end
  end
end
