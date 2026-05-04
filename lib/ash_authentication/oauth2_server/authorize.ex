# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.Authorize do
  @moduledoc """
  Protocol-pure logic for the `/oauth/authorize` endpoint.

  Controllers in `ash_authentication_phoenix` are thin wrappers around
  `validate_request/2`, `consented?/4`, `grant_consent!/4`, and
  `issue_code!/3`. None of these functions touch `Plug.Conn`.
  """

  require Ash.Query

  alias AshAuthentication.Oauth2Server

  @typedoc """
  The validated authorize-request payload. The struct is intentionally small —
  enough to render a consent screen and ultimately mint an authorization code.
  """
  @type validated :: %{
          client: Ash.Resource.record(),
          redirect_uri: String.t(),
          code_challenge: String.t(),
          scope: String.t(),
          state: String.t(),
          resource: String.t()
        }

  @doc """
  Validate an inbound authorize request.

  Returns:

    * `{:ok, validated}` — request is structurally sound and the client +
      redirect_uri are known.
    * `{:error, :bad_redirect_uri}` — redirect_uri is missing or doesn't
      match a registered URI; per RFC 6749 §4.1.2.1 the controller MUST NOT
      redirect.
    * `{:error, error_code, description}` — any other validation error.
      Controllers redirect these errors back to `redirect_uri`.
  """
  @spec validate_request(server :: module(), params :: map()) ::
          {:ok, validated()}
          | {:error, :bad_redirect_uri}
          | {:error, String.t(), String.t()}
  def validate_request(server, params) do
    with :ok <- require_eq(params, "response_type", "code", "unsupported_response_type"),
         {:ok, client} <- load_client(server, params),
         :ok <- check_redirect_uri(params, client),
         :ok <- require_eq(params, "code_challenge_method", "S256", "invalid_request"),
         {:ok, resource} <- resolve_resource(server, params),
         {:ok, code_challenge} <- require_present(params, "code_challenge"),
         {:ok, scope} <- require_present(params, "scope"),
         {:ok, redirect_uri} <- require_present(params, "redirect_uri"),
         {:ok, state} <- require_present(params, "state") do
      {:ok,
       %{
         client: client,
         redirect_uri: redirect_uri,
         code_challenge: code_challenge,
         scope: scope,
         state: state,
         resource: resource
       }}
    end
  end

  @doc """
  Has the user already consented to this client at a scope that covers the
  currently-requested scope?

  Returns true ONLY when prior consent exists AND its scope is a superset of
  `requested_scope`. This prevents silent privilege expansion when a client
  later asks for more scopes than the user originally agreed to.
  """
  @spec consented?(
          server :: module(),
          user :: Ash.Resource.record(),
          client :: Ash.Resource.record(),
          requested_scope :: String.t()
        ) :: boolean()
  def consented?(server, user, client, requested_scope) do
    server.consent_resource()
    |> Ash.Query.filter(user_id == ^user.id and client_id == ^client.id)
    |> Ash.read_one(authorize?: false)
    |> case do
      {:ok, %{scope: stored}} -> scope_covers?(stored, requested_scope)
      _ -> false
    end
  end

  @doc """
  Record (or refresh) a consent row for `(user, client)` at the given scope.
  """
  @spec grant_consent!(
          server :: module(),
          user :: Ash.Resource.record(),
          client :: Ash.Resource.record(),
          scope :: String.t()
        ) :: Ash.Resource.record()
  def grant_consent!(server, user, client, scope) do
    server.consent_resource()
    |> Ash.Changeset.for_create(:grant, %{
      user_id: user.id,
      client_id: client.id,
      scope: scope
    })
    |> Ash.create!(authorize?: false)
  end

  @doc """
  Mint a new short-lived authorization code bound to the user, client, scope,
  PKCE challenge, and resource URI.
  """
  @spec issue_code!(
          server :: module(),
          user :: Ash.Resource.record(),
          validated :: validated()
        ) :: Ash.Resource.record()
  def issue_code!(server, user, validated) do
    expires_at =
      DateTime.add(DateTime.utc_now(), server.authorization_code_lifetime(), :second)

    server.authorization_code_resource()
    |> Ash.Changeset.for_create(:create, %{
      client_id: validated.client.id,
      user_id: user.id,
      redirect_uri: validated.redirect_uri,
      code_challenge: validated.code_challenge,
      scope: validated.scope,
      resource_uri: validated.resource,
      expires_at: expires_at
    })
    |> Ash.create!(authorize?: false)
  end

  # ── helpers ──────────────────────────────────────────────────────────────

  defp require_eq(params, key, expected, error_code) do
    case Map.get(params, key) do
      ^expected -> :ok
      _ -> {:error, error_code, "expected #{key}=#{expected}"}
    end
  end

  defp require_present(params, key) do
    case Map.get(params, key) do
      v when is_binary(v) and v != "" -> {:ok, v}
      _ -> {:error, "invalid_request", "#{key} is required"}
    end
  end

  defp load_client(server, %{"client_id" => id}) do
    case Ash.get(server.client_resource(), id, authorize?: false) do
      {:ok, client} -> {:ok, client}
      _ -> {:error, "invalid_client", "unknown client_id"}
    end
  end

  defp load_client(_server, _params), do: {:error, "invalid_request", "client_id required"}

  defp check_redirect_uri(%{"redirect_uri" => uri}, %{redirect_uris: uris}) when is_list(uris) do
    if uri in uris, do: :ok, else: {:error, :bad_redirect_uri}
  end

  defp check_redirect_uri(_, _), do: {:error, :bad_redirect_uri}

  # `resource` is optional per RFC 8707 §2 — when absent, default to the
  # server's configured resource_url. When present, it MUST match.
  defp resolve_resource(server, %{"resource" => res}) when is_binary(res) and res != "" do
    if Oauth2Server.__normalize_url__(res) == server.resource_url(),
      do: {:ok, server.resource_url()},
      else: {:error, "invalid_target", "resource does not match this authorization server"}
  end

  defp resolve_resource(server, _), do: {:ok, server.resource_url()}

  defp scope_covers?(stored, requested) when is_binary(stored) and is_binary(requested) do
    stored_set = stored |> String.split(" ", trim: true) |> MapSet.new()
    requested_set = requested |> String.split(" ", trim: true) |> MapSet.new()
    MapSet.subset?(requested_set, stored_set)
  end

  defp scope_covers?(_, _), do: false
end
