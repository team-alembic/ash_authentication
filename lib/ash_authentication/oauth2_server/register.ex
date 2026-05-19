# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.Register do
  @moduledoc """
  Protocol-pure logic for `/oauth/register` (RFC 7591 Dynamic Client
  Registration).

  v1 supports public clients only (PKCE, `token_endpoint_auth_method: "none"`).
  Confidential clients (`client_secret_basic`) are deferred.

  Registration is open by default — the standard RFC 7591 mode. To gate
  it, set `:initial_access_token` on your `Oauth2Server` module and pass
  the request's bearer token via `opts[:initial_access_token]` when
  calling `register/3` (RFC 7591 §3).
  """

  @valid_grant_types ~w(authorization_code refresh_token)
  @valid_response_types ~w(code)
  @valid_auth_methods ~w(none)

  @doc """
  Register a new OAuth client from RFC 7591-shaped parameters.

  `opts` may include:

    * `:initial_access_token` — the bearer token the request presented
      (or `nil`). When the server has `:initial_access_token` configured,
      this MUST match (constant-time) or registration is rejected.

  Returns `{:ok, client_record, response_body}` on success or
  `{:error, code, description}` on a validation failure suitable for a
  400 DCR error response.
  """
  @spec register(server :: module(), params :: map(), opts :: keyword()) ::
          {:ok, Ash.Resource.record(), map()}
          | {:error, String.t(), String.t()}
  def register(server, params, opts \\ []) do
    with :ok <- check_initial_access_token(server, opts),
         :ok <- validate_redirect_uris(params),
         :ok <- validate_client_name(params),
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

  defp check_initial_access_token(server, opts) do
    case server.initial_access_token() do
      nil ->
        :ok

      expected when is_binary(expected) ->
        presented = Keyword.get(opts, :initial_access_token)

        if is_binary(presented) and Plug.Crypto.secure_compare(expected, presented),
          do: :ok,
          else:
            {:error, "invalid_client_metadata",
             "registration requires a valid initial access token"}
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

  # `client_name` is optional in RFC 7591. When present, must be a string;
  # we don't impose length limits but reject obviously bogus shapes so they
  # turn into a clean DCR error rather than a 500 in the changeset.
  defp validate_client_name(%{"client_name" => name}) when is_binary(name), do: :ok

  defp validate_client_name(%{"client_name" => _}),
    do: {:error, "invalid_client_metadata", "client_name must be a string"}

  defp validate_client_name(_), do: :ok

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
