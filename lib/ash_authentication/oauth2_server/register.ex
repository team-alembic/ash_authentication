# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.Register do
  @moduledoc """
  Protocol-pure logic for `/oauth/register` (RFC 7591 Dynamic Client
  Registration).

  v1 supports public clients only (PKCE, `token_endpoint_auth_method: "none"`).
  Confidential clients (`client_secret_basic`) are deferred.
  """

  @valid_grant_types ~w(authorization_code refresh_token)
  @valid_response_types ~w(code)
  @valid_auth_methods ~w(none)

  @doc """
  Register a new OAuth client from RFC 7591-shaped parameters.

  Returns `{:ok, client_record, response_body}` on success or
  `{:error, code, description}` on a validation failure suitable for a
  400 DCR error response.

  `response_body` is the map the controller should JSON-encode and return.
  """
  @spec register(server :: module(), params :: map()) ::
          {:ok, Ash.Resource.record(), map()}
          | {:error, String.t(), String.t()}
  def register(server, params) do
    with :ok <- validate_redirect_uris(params),
         :ok <- validate_grant_types(params),
         :ok <- validate_response_types(params),
         :ok <- validate_auth_method(params),
         {:ok, client} <- create_client(server, params) do
      {:ok, client, response_body(server, client)}
    else
      {:error, code, desc} -> {:error, code, desc}
      {:error, _other} -> {:error, "invalid_client_metadata", "client could not be registered"}
    end
  end

  defp validate_redirect_uris(%{"redirect_uris" => uris}) when is_list(uris) and uris != [] do
    Enum.reduce_while(uris, :ok, fn uri, _ ->
      case URI.new(uri) do
        {:ok, %URI{scheme: "https", host: host, fragment: nil}}
        when is_binary(host) and host != "" ->
          {:cont, :ok}

        {:ok, %URI{scheme: "http", host: host, fragment: nil}}
        when host in ["localhost", "127.0.0.1", "::1"] ->
          {:cont, :ok}

        _ ->
          {:halt,
           {:error, "invalid_redirect_uri",
            "redirect URIs must use https (or http localhost), have a host, and no fragment"}}
      end
    end)
  end

  defp validate_redirect_uris(_),
    do: {:error, "invalid_client_metadata", "redirect_uris is required"}

  defp validate_grant_types(%{"grant_types" => grants}) when is_list(grants) do
    if Enum.all?(grants, &(&1 in @valid_grant_types)),
      do: :ok,
      else: {:error, "invalid_client_metadata", "unsupported grant_type"}
  end

  defp validate_grant_types(_), do: :ok

  defp validate_response_types(%{"response_types" => types}) when is_list(types) do
    if Enum.all?(types, &(&1 in @valid_response_types)),
      do: :ok,
      else: {:error, "invalid_client_metadata", "unsupported response_type"}
  end

  defp validate_response_types(_), do: :ok

  defp validate_auth_method(%{"token_endpoint_auth_method" => m}) when m in @valid_auth_methods,
    do: :ok

  defp validate_auth_method(%{"token_endpoint_auth_method" => _}),
    do: {:error, "invalid_client_metadata", "unsupported token_endpoint_auth_method"}

  defp validate_auth_method(_), do: :ok

  defp create_client(server, params) do
    attrs = %{
      client_name: Map.get(params, "client_name", "Unnamed Client"),
      redirect_uris: Map.fetch!(params, "redirect_uris"),
      grant_types: Map.get(params, "grant_types", ["authorization_code"]),
      response_types: Map.get(params, "response_types", ["code"]),
      token_endpoint_auth_method: Map.get(params, "token_endpoint_auth_method", "none"),
      scope: Enum.join(server.scopes(), " ")
    }

    server.client_resource()
    |> Ash.Changeset.for_create(:register, attrs)
    |> Ash.create(authorize?: false)
  end

  defp response_body(server, client) do
    base = %{
      "client_id" => client.id,
      "client_id_issued_at" => DateTime.to_unix(client.inserted_at),
      "client_name" => client.client_name,
      "redirect_uris" => client.redirect_uris,
      "grant_types" => client.grant_types,
      "response_types" => client.response_types,
      "token_endpoint_auth_method" => client.token_endpoint_auth_method,
      "scope" => client.scope
    }

    if server.dcr_always_return_client_secret?() and
         client.token_endpoint_auth_method == "none" do
      Map.put(base, "client_secret", "")
    else
      base
    end
  end
end
