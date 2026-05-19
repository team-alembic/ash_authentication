# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.Metadata do
  @moduledoc """
  Builders for the discovery metadata endpoints.

    * `protected_resource/1` (RFC 9728) — for the resource server, served at
      `/.well-known/oauth-protected-resource`.
    * `authorization_server/1` (RFC 8414) — for the authorization server,
      served at `/.well-known/oauth-authorization-server`.

  Both return plain maps; controllers JSON-encode them.
  """

  @doc """
  Build the OAuth Protected Resource Metadata document (RFC 9728).
  """
  @spec protected_resource(server :: module()) :: map()
  def protected_resource(server) do
    %{
      "resource" => server.resource_url(),
      "authorization_servers" => [server.issuer_url()],
      "scopes_supported" => server.scopes(),
      "bearer_methods_supported" => ["header"]
    }
  end

  @doc """
  Build the OAuth Authorization Server Metadata document (RFC 8414).

  Endpoint paths are derived from the `issuer_url` so that mounting under a
  custom prefix works without configuration.
  """
  @spec authorization_server(server :: module()) :: map()
  def authorization_server(server) do
    issuer = server.issuer_url()

    %{
      "issuer" => issuer,
      "authorization_endpoint" => issuer <> "/oauth/authorize",
      "token_endpoint" => issuer <> "/oauth/token",
      "registration_endpoint" => issuer <> "/oauth/register",
      "revocation_endpoint" => issuer <> "/oauth/revoke",
      "response_types_supported" => ["code"],
      "grant_types_supported" => ["authorization_code", "refresh_token"],
      "code_challenge_methods_supported" => ["S256"],
      "token_endpoint_auth_methods_supported" => ["none"],
      "scopes_supported" => server.scopes()
    }
  end
end
