# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.FlowTest do
  @moduledoc """
  End-to-end protocol-level flow test.

  Exercises Authorize → consume code → Token (auth_code grant) → Token
  (refresh grant) → Token (refresh reuse → chain revocation) against real
  Ash resources backed by ETS, with no Plug or HTTP layer in the picture.
  """
  use ExUnit.Case, async: false

  alias AshAuthentication.Oauth2Server.{Authorize, Jwt, PKCE, Register, Token}
  alias Oauth2ServerTest.Server

  alias Oauth2ServerTest.{
    OAuthAuthorizationCode,
    OAuthClient,
    OAuthConsent,
    OAuthRefreshToken,
    User
  }

  setup do
    # Clear ETS between tests; ETS data layer persists across tests by default.
    for resource <- [OAuthClient, OAuthAuthorizationCode, OAuthRefreshToken, OAuthConsent, User] do
      Ash.bulk_destroy!(resource, :destroy, %{}, return_errors?: true)
    end

    user =
      User
      |> Ash.Changeset.for_create(:create, %{email: "alice@example.com"})
      |> Ash.create!()

    {:ok, user: user}
  end

  defp register_client(redirect_uri \\ "https://chat.example.com/cb") do
    {:ok, client, body} =
      Register.register(Server, %{
        "client_name" => "Test Client",
        "redirect_uris" => [redirect_uri]
      })

    {client, body}
  end

  defp pkce_pair do
    verifier = Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false)
    {verifier, PKCE.challenge(verifier)}
  end

  defp authorize_params(client, code_challenge, redirect_uri) do
    %{
      "response_type" => "code",
      "client_id" => client.id,
      "redirect_uri" => redirect_uri,
      "code_challenge" => code_challenge,
      "code_challenge_method" => "S256",
      "scope" => "mcp",
      "state" => "csrf-state",
      "resource" => Server.resource_url()
    }
  end

  describe "Register (DCR)" do
    test "happy path returns client + body" do
      {client, body} = register_client()

      assert client.client_name == "Test Client"
      assert client.redirect_uris == ["https://chat.example.com/cb"]
      assert client.grant_types == ["authorization_code"]
      assert client.token_endpoint_auth_method == "none"
      assert body["client_id"] == client.id
      assert body["scope"] == "mcp"
      refute Map.has_key?(body, "client_secret")
    end

    test "rejects missing redirect_uris" do
      assert {:error, "invalid_client_metadata", _} =
               Register.register(Server, %{"client_name" => "X"})
    end

    test "rejects http non-localhost redirects" do
      assert {:error, "invalid_redirect_uri", _} =
               Register.register(Server, %{
                 "client_name" => "X",
                 "redirect_uris" => ["http://attacker.example.com/cb"]
               })
    end

    test "accepts http localhost" do
      assert {:ok, _, _} =
               Register.register(Server, %{
                 "client_name" => "Local",
                 "redirect_uris" => ["http://localhost:4000/cb"]
               })
    end

    test "rejects non-string client_name with a clean DCR error" do
      assert {:error, "invalid_client_metadata", desc} =
               Register.register(Server, %{
                 "client_name" => 1234,
                 "redirect_uris" => ["https://app.example.com/cb"]
               })

      assert desc =~ "client_name"
    end

    test "open server ignores any presented initial access token" do
      # Server has no initial_access_token configured — presenting one
      # is a no-op rather than an error.
      assert {:ok, _, _} =
               Register.register(
                 Server,
                 %{"client_name" => "X", "redirect_uris" => ["https://app.example.com/cb"]},
                 initial_access_token: "anything"
               )
    end

    test "gated server rejects registration without an initial access token" do
      # RFC 7591 §3.2.2 — this is a Bearer-auth failure (the
      # controller must emit 401 with WWW-Authenticate), not a
      # `invalid_client_metadata` 400.
      assert {:error, :invalid_initial_access_token} =
               Register.register(Oauth2ServerTest.GatedServer, %{
                 "client_name" => "X",
                 "redirect_uris" => ["https://app.example.com/cb"]
               })
    end

    test "gated server rejects a wrong initial access token" do
      assert {:error, :invalid_initial_access_token} =
               Register.register(
                 Oauth2ServerTest.GatedServer,
                 %{"client_name" => "X", "redirect_uris" => ["https://app.example.com/cb"]},
                 initial_access_token: "wrong-token"
               )
    end

    test "gated server accepts registration with the correct initial access token" do
      assert {:ok, _client, body} =
               Register.register(
                 Oauth2ServerTest.GatedServer,
                 %{"client_name" => "Trusted", "redirect_uris" => ["https://app.example.com/cb"]},
                 initial_access_token: "test-initial-access-token-shhh"
               )

      assert body["client_name"] == "Trusted"
    end
  end

  describe "Authorize.validate_request/2" do
    test "happy path returns the validated request", %{user: _user} do
      {client, _} = register_client()
      {_verifier, challenge} = pkce_pair()
      params = authorize_params(client, challenge, "https://chat.example.com/cb")

      assert {:ok, validated} = Authorize.validate_request(Server, params)
      assert validated.client.id == client.id
      assert validated.scope == "mcp"
      assert validated.code_challenge == challenge
    end

    test "rejects unknown client_id" do
      {_verifier, challenge} = pkce_pair()

      params =
        authorize_params(%{id: Ash.UUIDv7.generate()}, challenge, "https://chat.example.com/cb")

      assert {:error, "invalid_client", _} = Authorize.validate_request(Server, params)
    end

    test "rejects mismatched redirect_uri without leaking via redirect" do
      {client, _} = register_client()
      {_, challenge} = pkce_pair()
      params = authorize_params(client, challenge, "https://attacker.example.com/cb")

      assert {:error, :bad_redirect_uri} = Authorize.validate_request(Server, params)
    end

    test "redirect_uri must match the registered value byte-for-byte (RFC 9700 §4.1)" do
      {client, _} = register_client("https://chat.example.com/cb")
      {_, challenge} = pkce_pair()

      # Equivalent-but-not-identical URIs are rejected — no trailing-slash,
      # case, default-port, or fragment equivalence.
      for incoming <- [
            "https://chat.example.com/cb/",
            "HTTPS://CHAT.EXAMPLE.COM/cb",
            "https://chat.example.com:443/cb",
            "https://chat.example.com/cb#frag"
          ] do
        params = authorize_params(client, challenge, incoming)
        assert {:error, :bad_redirect_uri} = Authorize.validate_request(Server, params)
      end

      # The exact registered value passes.
      params = authorize_params(client, challenge, "https://chat.example.com/cb")
      assert {:ok, _} = Authorize.validate_request(Server, params)
    end

    test "accepts a scope that's a subset of the server's catalogue" do
      # Server is configured with scopes: ["mcp"]; requesting "mcp" alone is fine.
      {client, _} = register_client()
      {_, challenge} = pkce_pair()
      params = authorize_params(client, challenge, "https://chat.example.com/cb")

      assert {:ok, _} = Authorize.validate_request(Server, params)
    end

    test "rejects a scope that includes a value outside the server's catalogue" do
      {client, _} = register_client()
      {_, challenge} = pkce_pair()

      params =
        client
        |> authorize_params(challenge, "https://chat.example.com/cb")
        |> Map.put("scope", "mcp admin")

      assert {:error, "invalid_scope", desc} = Authorize.validate_request(Server, params)
      assert desc =~ "admin"
    end

    test "resolves a scope catalogue from an MFA tuple" do
      # DynamicScopesServer's :scopes is {ScopeProvider, :list_scopes, []}.
      # The catalogue is ["mcp", "dynamic.scope"]; "dynamic.scope" alone
      # should be acceptable.
      {:ok, client, _} =
        Register.register(Oauth2ServerTest.DynamicScopesServer, %{
          "client_name" => "X",
          "redirect_uris" => ["https://chat.example.com/cb"]
        })

      {_, challenge} = pkce_pair()

      params =
        client
        |> authorize_params(challenge, "https://chat.example.com/cb")
        |> Map.put("scope", "dynamic.scope")

      assert {:ok, _} =
               Authorize.validate_request(Oauth2ServerTest.DynamicScopesServer, params)

      # And a scope OUTSIDE the dynamically-resolved list still gets rejected.
      bad =
        client
        |> authorize_params(challenge, "https://chat.example.com/cb")
        |> Map.put("scope", "not.in.catalogue")

      assert {:error, "invalid_scope", _} =
               Authorize.validate_request(Oauth2ServerTest.DynamicScopesServer, bad)
    end

    test "with enforce_scopes?: false, accepts scopes outside the catalogue" do
      # Register against the unenforced server using its own client resource
      # (same resource — multiple servers can share the OAuthClient table in
      # tests).
      {:ok, client, _body} =
        Register.register(Oauth2ServerTest.UnenforcedScopesServer, %{
          "client_name" => "X",
          "redirect_uris" => ["https://chat.example.com/cb"]
        })

      {_, challenge} = pkce_pair()

      params =
        client
        |> authorize_params(challenge, "https://chat.example.com/cb")
        |> Map.put("scope", "mcp admin custom:foo")

      assert {:ok, %{scope: "mcp admin custom:foo"}} =
               Authorize.validate_request(Oauth2ServerTest.UnenforcedScopesServer, params)
    end

    test "rejects code_challenge_method=plain (S256 only)" do
      {client, _} = register_client()
      {_, challenge} = pkce_pair()

      params =
        client
        |> authorize_params(challenge, "https://chat.example.com/cb")
        |> Map.put("code_challenge_method", "plain")

      assert {:error, "invalid_request", _} = Authorize.validate_request(Server, params)
    end

    test "rejects mismatched resource (audience binding)" do
      {client, _} = register_client()
      {_, challenge} = pkce_pair()

      params =
        client
        |> authorize_params(challenge, "https://chat.example.com/cb")
        |> Map.put("resource", "https://attacker.example.com/")

      assert {:error, "invalid_target", desc} = Authorize.validate_request(Server, params)
      # Echoes the expected URL (server-controlled) so clients can debug;
      # does NOT echo the user-supplied resource value back.
      assert desc =~ Server.resource_url()
      refute desc =~ "attacker.example.com"
    end
  end

  describe "consent" do
    test "consented?/4 false until granted, true after, scope-superset matters", %{user: user} do
      {client, _} = register_client()

      refute Authorize.consented?(Server, user, client, "mcp")

      Authorize.grant_consent!(Server, user, client, "mcp")
      assert Authorize.consented?(Server, user, client, "mcp")

      # asking for a wider scope than was granted should fail
      refute Authorize.consented?(Server, user, client, "mcp admin")
    end
  end

  describe "authorization_code grant" do
    test "round-trip: validate → issue code → exchange for tokens", %{user: user} do
      {client, _} = register_client()
      {verifier, challenge} = pkce_pair()
      auth_params = authorize_params(client, challenge, "https://chat.example.com/cb")

      {:ok, validated} = Authorize.validate_request(Server, auth_params)
      code_record = Authorize.issue_code!(Server, user, validated)

      token_params = %{
        "grant_type" => "authorization_code",
        "code" => code_record.id,
        "redirect_uri" => "https://chat.example.com/cb",
        "code_verifier" => verifier,
        "client_id" => client.id,
        "resource" => Server.resource_url()
      }

      assert {:ok, response} = Token.exchange_authorization_code(Server, token_params)
      assert response.token_type == "Bearer"
      assert response.scope == "mcp"
      assert is_binary(response.access_token)
      assert is_binary(response.refresh_token)
      assert response.expires_in == Server.access_token_lifetime()

      # access token verifies under the audience
      assert {:ok, claims} = Jwt.verify(Server, response.access_token)

      assert claims["sub"] == user.id
      assert claims["client_id"] == client.id
      assert claims["scope"] == "mcp"
    end

    test "rejects re-using an already-consumed code", %{user: user} do
      {client, _} = register_client()
      {verifier, challenge} = pkce_pair()

      {:ok, validated} =
        Authorize.validate_request(
          Server,
          authorize_params(client, challenge, "https://chat.example.com/cb")
        )

      code = Authorize.issue_code!(Server, user, validated)

      params = %{
        "grant_type" => "authorization_code",
        "code" => code.id,
        "redirect_uri" => "https://chat.example.com/cb",
        "code_verifier" => verifier,
        "client_id" => client.id,
        "resource" => Server.resource_url()
      }

      assert {:ok, _} = Token.exchange_authorization_code(Server, params)
      assert {:error, :reuse} = Token.exchange_authorization_code(Server, params)
    end

    test "rejects bad PKCE verifier", %{user: user} do
      {client, _} = register_client()
      {_real_verifier, challenge} = pkce_pair()

      {:ok, validated} =
        Authorize.validate_request(
          Server,
          authorize_params(client, challenge, "https://chat.example.com/cb")
        )

      code = Authorize.issue_code!(Server, user, validated)

      assert {:error, :pkce} =
               Token.exchange_authorization_code(Server, %{
                 "grant_type" => "authorization_code",
                 "code" => code.id,
                 "redirect_uri" => "https://chat.example.com/cb",
                 "code_verifier" => "wrong",
                 "client_id" => client.id,
                 "resource" => Server.resource_url()
               })
    end

    test "rejects mismatched redirect_uri at token time", %{user: user} do
      {client, _} = register_client()
      {verifier, challenge} = pkce_pair()

      {:ok, validated} =
        Authorize.validate_request(
          Server,
          authorize_params(client, challenge, "https://chat.example.com/cb")
        )

      code = Authorize.issue_code!(Server, user, validated)

      assert {:error, :redirect_mismatch} =
               Token.exchange_authorization_code(Server, %{
                 "grant_type" => "authorization_code",
                 "code" => code.id,
                 "redirect_uri" => "https://other.example.com/cb",
                 "code_verifier" => verifier,
                 "client_id" => client.id,
                 "resource" => Server.resource_url()
               })
    end

    test "rejects an equivalent-but-not-identical redirect_uri at token time (RFC 9700 §4.1)", %{
      user: user
    } do
      {client, _} = register_client("https://chat.example.com/cb")
      {verifier, challenge} = pkce_pair()

      {:ok, validated} =
        Authorize.validate_request(
          Server,
          authorize_params(client, challenge, "https://chat.example.com/cb")
        )

      code = Authorize.issue_code!(Server, user, validated)

      # Same URI with different surface form (case + default port +
      # trailing slash) — RFC 9700 requires byte-exact match.
      assert {:error, :redirect_mismatch} =
               Token.exchange_authorization_code(Server, %{
                 "grant_type" => "authorization_code",
                 "code" => code.id,
                 "redirect_uri" => "HTTPS://CHAT.EXAMPLE.COM:443/cb/",
                 "code_verifier" => verifier,
                 "client_id" => client.id,
                 "resource" => Server.resource_url()
               })
    end
  end

  describe "refresh_token grant" do
    test "rotates: old refresh stops working, new one works once", %{user: user} do
      {client, _} = register_client()
      {verifier, challenge} = pkce_pair()

      {:ok, validated} =
        Authorize.validate_request(
          Server,
          authorize_params(client, challenge, "https://chat.example.com/cb")
        )

      code = Authorize.issue_code!(Server, user, validated)

      {:ok, first} =
        Token.exchange_authorization_code(Server, %{
          "grant_type" => "authorization_code",
          "code" => code.id,
          "redirect_uri" => "https://chat.example.com/cb",
          "code_verifier" => verifier,
          "client_id" => client.id,
          "resource" => Server.resource_url()
        })

      refresh_params = fn rt ->
        %{
          "grant_type" => "refresh_token",
          "refresh_token" => rt,
          "client_id" => client.id,
          "resource" => Server.resource_url()
        }
      end

      assert {:ok, second} =
               Token.exchange_refresh_token(Server, refresh_params.(first.refresh_token))

      assert second.refresh_token != first.refresh_token

      # Reuse of the original refresh token after rotation is detected and
      # revokes the chain.
      assert {:error, :reuse} =
               Token.exchange_refresh_token(Server, refresh_params.(first.refresh_token))

      # The new refresh token is now also revoked because of chain revocation.
      assert {:error, :revoked} =
               Token.exchange_refresh_token(Server, refresh_params.(second.refresh_token))
    end
  end
end
