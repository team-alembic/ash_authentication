# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.SmokeTest do
  @moduledoc """
  Foundation smoke test for the OAuth2Server core. Exercises configuration
  resolution, PKCE, and JWT mint/verify without bringing up Ash resources.
  Resource-driven flow tests live in separate files.
  """
  use ExUnit.Case, async: true

  alias AshAuthentication.Oauth2Server
  alias AshAuthentication.Oauth2Server.{Jwt, Metadata, PKCE}

  defmodule Secrets do
    use AshAuthentication.Secret

    @impl AshAuthentication.Secret
    def secret_for([:issuer_url], _, _, _), do: {:ok, "https://app.example.com/"}
    def secret_for([:resource_url], _, _, _), do: {:ok, "https://app.example.com/mcp"}

    def secret_for([:signing_secret], _, _, _),
      do: {:ok, "test-signing-secret-test-signing-secret"}

    def secret_for(_, _, _, _), do: :error
  end

  defmodule TestServer do
    use AshAuthentication.Oauth2Server,
      otp_app: :ash_authentication,
      user_resource: TestServerStubUser,
      issuer_url: {Secrets, []},
      resource_url: {Secrets, []},
      signing_secret: {Secrets, []},
      client_resource: TestServerStubClient,
      authorization_code_resource: TestServerStubCode,
      refresh_token_resource: TestServerStubRefresh,
      consent_resource: TestServerStubConsent,
      access_token_lifetime: {15, :minutes},
      refresh_token_lifetime: {7, :days},
      scopes: ["mcp", "read"],
      dcr_enabled?: true
  end

  describe "configuration resolution" do
    test "literal options return as configured" do
      assert TestServer.otp_app() == :ash_authentication
      assert TestServer.scopes() == ["mcp", "read"]
      assert TestServer.dcr_always_return_client_secret?() == false
    end

    test "lifetimes convert to seconds" do
      assert TestServer.access_token_lifetime() == 15 * 60
      assert TestServer.refresh_token_lifetime() == 7 * 24 * 60 * 60
      assert TestServer.authorization_code_lifetime() == 10 * 60
    end

    test "secret-resolved URLs are normalized" do
      # input "https://app.example.com/" — trailing slash stripped
      assert TestServer.issuer_url() == "https://app.example.com"
      assert TestServer.resource_url() == "https://app.example.com/mcp"
    end

    test "signing_secret is resolved through the Secret behaviour" do
      assert TestServer.signing_secret() == "test-signing-secret-test-signing-secret"
    end
  end

  describe "PKCE (RFC 7636)" do
    test "challenge from a known verifier matches the spec example" do
      # RFC 7636 Appendix B
      verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
      expected = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
      assert PKCE.challenge(verifier) == expected
      assert PKCE.verify(verifier, expected) == :ok
    end

    test "verify rejects mismatches and bad input" do
      assert PKCE.verify("not_the_verifier", "expected") == :error
      assert PKCE.verify(nil, "expected") == :error
      assert PKCE.verify("verifier", nil) == :error
    end
  end

  describe "JWT mint/verify" do
    test "minted token round-trips and carries all required claims" do
      assert {:ok, token, claims} =
               Jwt.mint(TestServer,
                 sub: "user-123",
                 client_id: "client-abc",
                 scope: "mcp"
               )

      assert is_binary(token)
      assert claims["iss"] == TestServer.issuer_url()
      assert claims["sub"] == "user-123"
      assert claims["aud"] == TestServer.resource_url()
      assert claims["client_id"] == "client-abc"
      assert claims["scope"] == "mcp"
      assert is_integer(claims["iat"])
      assert claims["exp"] == claims["iat"] + TestServer.access_token_lifetime()
      assert is_binary(claims["jti"])

      assert {:ok, verified} = Jwt.verify(TestServer, token)
      assert verified["sub"] == "user-123"
    end

    test "tokens with the wrong audience are rejected" do
      # Mint with our server, then alter the audience and resign with the
      # same secret to prove the audience check kicks in independently of
      # signature verification.
      {:ok, _, claims} =
        Jwt.mint(TestServer, sub: "u1", client_id: "c1", scope: "mcp")

      tampered = %{claims | "aud" => "https://attacker.example.com"}
      signer = Joken.Signer.create("HS256", TestServer.signing_secret())
      {:ok, bad_token, _} = Joken.encode_and_sign(tampered, signer)

      assert {:error, :invalid_audience} = Jwt.verify(TestServer, bad_token)
    end

    test "tokens signed with a different secret are rejected" do
      bad_signer = Joken.Signer.create("HS256", "different-secret-different-secret")

      claims = %{
        "iss" => TestServer.issuer_url(),
        "sub" => "u1",
        "aud" => TestServer.resource_url(),
        "exp" => System.system_time(:second) + 60
      }

      {:ok, bad_token, _} = Joken.encode_and_sign(claims, bad_signer)
      assert {:error, _} = Jwt.verify(TestServer, bad_token)
    end

    test "tokens expired beyond the clock-skew window are rejected" do
      # Beyond the default 30-second skew tolerance.
      claims = %{
        "iss" => TestServer.issuer_url(),
        "sub" => "u1",
        "aud" => TestServer.resource_url(),
        "exp" => System.system_time(:second) - 120
      }

      signer = Joken.Signer.create("HS256", TestServer.signing_secret())
      {:ok, expired, _} = Joken.encode_and_sign(claims, signer)

      assert {:error, :expired} = Jwt.verify(TestServer, expired)
    end

    test "tokens expired within the clock-skew window still verify (RFC 7519 §4.1.4)" do
      # 5 seconds past `exp` — within the default 30-second skew tolerance.
      claims = %{
        "iss" => TestServer.issuer_url(),
        "sub" => "u1",
        "aud" => TestServer.resource_url(),
        "exp" => System.system_time(:second) - 5
      }

      signer = Joken.Signer.create("HS256", TestServer.signing_secret())
      {:ok, slightly_expired, _} = Joken.encode_and_sign(claims, signer)

      assert {:ok, _} = Jwt.verify(TestServer, slightly_expired)
    end

    test "tokens whose `nbf` is in the future beyond skew are rejected" do
      claims = %{
        "iss" => TestServer.issuer_url(),
        "sub" => "u1",
        "aud" => TestServer.resource_url(),
        "nbf" => System.system_time(:second) + 120,
        "exp" => System.system_time(:second) + 300
      }

      signer = Joken.Signer.create("HS256", TestServer.signing_secret())
      {:ok, future_token, _} = Joken.encode_and_sign(claims, signer)

      assert {:error, :not_yet_valid} = Jwt.verify(TestServer, future_token)
    end

    test "tokens with `nbf` slightly in the future verify within skew" do
      claims = %{
        "iss" => TestServer.issuer_url(),
        "sub" => "u1",
        "aud" => TestServer.resource_url(),
        "nbf" => System.system_time(:second) + 5,
        "exp" => System.system_time(:second) + 300
      }

      signer = Joken.Signer.create("HS256", TestServer.signing_secret())
      {:ok, edge_token, _} = Joken.encode_and_sign(claims, signer)

      assert {:ok, _} = Jwt.verify(TestServer, edge_token)
    end
  end

  describe "discovery metadata documents" do
    test "protected_resource/1 (RFC 9728) lists this server as the AS" do
      doc = Metadata.protected_resource(TestServer)

      assert doc["resource"] == TestServer.resource_url()
      assert doc["authorization_servers"] == [TestServer.issuer_url()]
      assert doc["scopes_supported"] == TestServer.scopes()
      assert doc["bearer_methods_supported"] == ["header"]
    end

    test "authorization_server/1 (RFC 8414) advertises the standard endpoints" do
      doc = Metadata.authorization_server(TestServer)
      issuer = TestServer.issuer_url()

      assert doc["issuer"] == issuer
      assert doc["authorization_endpoint"] == issuer <> "/oauth/authorize"
      assert doc["token_endpoint"] == issuer <> "/oauth/token"
      assert doc["registration_endpoint"] == issuer <> "/oauth/register"
      assert doc["revocation_endpoint"] == issuer <> "/oauth/revoke"
      assert doc["response_types_supported"] == ["code"]
      assert doc["grant_types_supported"] == ["authorization_code", "refresh_token"]
      assert doc["code_challenge_methods_supported"] == ["S256"]
    end

    test "authorization_server/1 omits registration_endpoint when DCR is disabled" do
      doc = Metadata.authorization_server(Oauth2ServerTest.DcrDisabledServer)

      refute Map.has_key?(doc, "registration_endpoint")
      # Other endpoints still present.
      assert is_binary(doc["authorization_endpoint"])
      assert is_binary(doc["token_endpoint"])
    end
  end

  describe "URL normalization" do
    test "lowercases scheme + host, strips trailing slash, drops fragment" do
      assert Oauth2Server.__normalize_url__("HTTPS://APP.EXAMPLE.COM/") ==
               "https://app.example.com"

      assert Oauth2Server.__normalize_url__("https://app.example.com/mcp/#frag") ==
               "https://app.example.com/mcp"

      assert Oauth2Server.__normalize_url__("https://APP.example.com:4001/Mcp") ==
               "https://app.example.com:4001/Mcp"
    end

    test "elides default ports (RFC 8252 §7.3 / RFC 3986 §6)" do
      assert Oauth2Server.__normalize_url__("https://app.example.com:443/cb") ==
               "https://app.example.com/cb"

      assert Oauth2Server.__normalize_url__("http://app.example.com:80/cb") ==
               "http://app.example.com/cb"

      # Non-default ports are preserved.
      assert Oauth2Server.__normalize_url__("https://app.example.com:8443/cb") ==
               "https://app.example.com:8443/cb"

      # Default port on the wrong scheme is preserved (it's not default for http).
      assert Oauth2Server.__normalize_url__("http://app.example.com:443/cb") ==
               "http://app.example.com:443/cb"
    end

    test "trailing-slash + default port + case all canonicalize to the same form" do
      forms = [
        "https://app.example.com/cb",
        "https://app.example.com/cb/",
        "HTTPS://APP.EXAMPLE.COM/cb",
        "https://app.example.com:443/cb",
        "https://APP.EXAMPLE.COM:443/cb/",
        "https://app.example.com/cb#fragment"
      ]

      [first | rest] = Enum.map(forms, &Oauth2Server.__normalize_url__/1)
      assert Enum.all?(rest, &(&1 == first))
    end
  end
end
