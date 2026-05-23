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
           code_or_error(Ash.get(server.client_resource(), code.client_id, authorize?: false)) do
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
  rotation + reuse detection (OAuth 2.1 §4.3.1): a second use of an
  already-rotated refresh token returns `{:error, :reuse}` and revokes the
  descendant chain.

  The rotation is atomic at the data-layer level — every "is this
  refresh usable" check lives in the `:rotate` action's filter, so
  validate + rotate is one query in the happy path. On a 0-row result
  (race lost, invalid token, expired, etc.) we do a follow-up read to
  distinguish `:reuse` from the other failure modes.
  """
  @spec exchange_refresh_token(server :: module(), params :: map()) ::
          {:ok, token_response()} | {:error, atom()}
  def exchange_refresh_token(server, %{"refresh_token" => raw, "client_id" => client_id} = params)
      when is_binary(raw) do
    hash = hash_refresh(raw)
    resource = Map.get(params, "resource")
    expected_resource = server.resource_url()

    # Allocate the new refresh row's identifiers upfront so the rotate
    # can atomically set `rotated_to_id = ^new_id` without a separate
    # round-trip.
    {new_raw, new_hash} = generate_refresh()
    new_id = Ash.UUIDv7.generate()

    case atomic_rotate(server, hash, client_id, resource, expected_resource, new_id) do
      {:ok, old_row} ->
        complete_rotation(server, old_row, new_id, new_hash, new_raw)

      :no_match ->
        case disambiguate_failure(server, hash, client_id, expected_resource, resource) do
          :reuse ->
            revoke_chain(server, hash)
            {:error, :reuse}

          other ->
            {:error, other}
        end

      {:bulk_error, errors} ->
        # The bulk update itself failed for a real reason (validation,
        # constraint, DB connectivity, etc.). Log it for ops visibility,
        # don't leak details to the caller, and skip the disambiguation
        # read — we already know the operation didn't complete.
        Logger.error("Oauth2Server: refresh-token bulk_update failed: " <> inspect(errors))

        {:error, :invalid_refresh}
    end
  end

  def exchange_refresh_token(_, _), do: {:error, :invalid_request}

  # The bulk update's filter holds every "is this refresh usable" check
  # in one place — client/resource/expiry/rotation/revocation — so the
  # whole "validate + rotate" step is one atomic operation. Returns:
  #
  #   * `{:ok, old_row}` — happy path; old row data is used to issue
  #     the new refresh + mint the access token.
  #   * `:no_match` — the filter matched zero rows. The caller does a
  #     follow-up read to distinguish `:reuse` (chain-revoke) from
  #     other invalid-grant cases.
  #   * `{:bulk_error, errors}` — the bulk update itself failed for a
  #     real reason (validation, constraint, etc.). The caller logs
  #     and returns a generic invalid_refresh without disambiguating.
  defp atomic_rotate(server, hash, client_id, resource, expected_resource, new_id) do
    if requested_resource_ok?(resource, expected_resource),
      do: do_atomic_rotate(server, hash, client_id, expected_resource, new_id),
      else: :no_match
  end

  defp do_atomic_rotate(server, hash, client_id, expected_resource, new_id) do
    now = DateTime.utc_now()

    server.refresh_token_resource()
    |> Ash.Query.filter(
      token_hash == ^hash and
        client_id == ^client_id and
        resource_uri == ^expected_resource and
        expires_at > ^now and
        is_nil(rotated_to_id) and
        is_nil(revoked_at)
    )
    |> Ash.bulk_update(:rotate, %{rotated_to_id: new_id},
      return_records?: true,
      return_errors?: true,
      authorize?: false
    )
    |> case do
      %Ash.BulkResult{status: :success, records: [old_row | _]} -> {:ok, old_row}
      %Ash.BulkResult{status: :success} -> :no_match
      %Ash.BulkResult{status: :error, errors: errors} -> {:bulk_error, errors}
    end
  end

  defp complete_rotation(server, old_row, new_id, new_hash, new_raw) do
    new_expires_at =
      DateTime.add(DateTime.utc_now(), server.refresh_token_lifetime(), :second)

    with {:ok, _new_row} <-
           server.refresh_token_resource()
           |> Ash.Changeset.for_create(:issue, %{
             id: new_id,
             token_hash: new_hash,
             client_id: old_row.client_id,
             user_id: old_row.user_id,
             scope: old_row.scope,
             resource_uri: old_row.resource_uri,
             expires_at: new_expires_at
           })
           |> Ash.create(authorize?: false),
         {:ok, access_token, _claims} <-
           Jwt.mint(server,
             sub: old_row.user_id,
             client_id: old_row.client_id,
             scope: old_row.scope
           ) do
      touch_client_by_id(server, old_row.client_id)

      {:ok,
       %{
         access_token: access_token,
         token_type: "Bearer",
         expires_in: server.access_token_lifetime(),
         refresh_token: new_raw,
         scope: old_row.scope
       }}
    end
  end

  # Re-read by hash on a 0-row update to figure out *why* the filter
  # didn't match. The atom returned drives both the public error and
  # the chain-revoke decision (only `:reuse` triggers revocation).
  # We could do this with errors on the bulk_update's filter instead
  # but not all data layers support that
  defp disambiguate_failure(server, hash, client_id, expected_resource, resource) do
    case find_refresh(server, hash) do
      {:ok, row} -> classify_row(row, client_id, expected_resource, resource)
      {:error, _} -> :invalid_refresh
    end
  end

  defp classify_row(row, client_id, expected_resource, resource) do
    cond do
      row.client_id != client_id -> :client_mismatch
      row.resource_uri != expected_resource -> :resource_mismatch
      not requested_resource_ok?(resource, expected_resource) -> :resource_mismatch
      row.revoked_at -> :revoked
      row.rotated_to_id -> :reuse
      DateTime.compare(DateTime.utc_now(), row.expires_at) == :gt -> :expired
      true -> :invalid_refresh
    end
  end

  @doc """
  Revoke a token per RFC 7009. Always returns `:ok` regardless of whether the
  token existed, was already revoked, or belonged to a different client — the
  RFC requires the endpoint not to leak token state.

  Only refresh tokens are revocable here: access tokens are stateless JWTs.
  When a refresh token is revoked, the entire descendant chain (rotated-to
  successors) is also revoked, so a refresh that has been rotated through
  cannot resurrect the session.

  The `params` map mirrors what RFC 7009 §2.1 sends to the endpoint:

    * `"token"` (required) — the raw token string the client wishes to revoke.
    * `"client_id"` (required) — the public client identifier.
    * `"token_type_hint"` (optional) — `"refresh_token"` or `"access_token"`.
      Treated as a hint only; access-token revocation is a silent no-op.
  """
  @spec revoke(server :: module(), params :: map()) :: :ok
  def revoke(server, %{"token" => raw, "client_id" => client_id})
      when is_binary(raw) and raw != "" and is_binary(client_id) and client_id != "" do
    hash = hash_refresh(raw)

    case find_refresh(server, hash) do
      {:ok, %{client_id: ^client_id} = row} -> revoke_descendants(server, row)
      _ -> :ok
    end

    :ok
  rescue
    _ -> :ok
  end

  def revoke(_server, _params), do: :ok

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

  # `resource` is optional per RFC 8707 §2 — when absent (`nil` or empty
  # string) we don't enforce, otherwise it must canonicalize to the
  # server's resource URL.
  defp requested_resource_ok?(nil, _expected), do: true
  defp requested_resource_ok?("", _expected), do: true

  defp requested_resource_ok?(bin, expected) when is_binary(bin) do
    AshAuthentication.Oauth2Server.__normalize_url__(bin) == expected
  end

  defp requested_resource_ok?(_, _), do: false

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
