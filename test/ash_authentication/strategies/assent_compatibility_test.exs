# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.AssentCompatibilityTest do
  @moduledoc false
  # The adapter override is application configuration, so these tests run serially.
  use DataCase, async: false
  import Plug.Conn
  import Plug.Test

  alias AshAuthentication.{Info, Strategy.Microsoft, Strategy.OAuth2.Plug, Strategy.Oidc.Verifier}
  alias AshAuthentication.Strategy.Microsoft.AzureADMultitenant
  alias Assent.Strategy.{CallbackCSRFError, OIDC}
  alias Spark.Error.DslError

  @issuer "https://issuer.example"
  @client_id "client:id"
  @secret "secret&value"
  @tenant "00000000-0000-0000-0000-000000000001"

  defmodule CaptureConfig do
    @moduledoc false
    @behaviour Assent.Strategy
    @impl true
    def authorize_url(config) do
      send(self(), {:config, config})
      {:ok, %{session_params: %{state: "state"}, url: "https://issuer.example/authorize"}}
    end

    @impl true
    def callback(_config, _params), do: {:error, :not_implemented}
  end

  setup do
    old = Application.fetch_env(:ash_authentication, :http_adapter)
    Application.delete_env(:ash_authentication, :http_adapter)

    on_exit(fn ->
      case old do
        {:ok, adapter} -> Application.put_env(:ash_authentication, :http_adapter, adapter)
        :error -> Application.delete_env(:ash_authentication, :http_adapter)
      end
    end)

    :ok
  end

  test "Req is the default adapter, and an explicit custom adapter is preserved" do
    strategy = Info.strategy!(Example.User, :oauth2)
    assert request_config(strategy)[:http_adapter] == Assent.HTTPAdapter.Req

    adapter = {Assent.HTTPAdapter.Req, plug: {Req.Test, __MODULE__}}
    Application.put_env(:ash_authentication, :http_adapter, adapter)
    assert request_config(strategy)[:http_adapter] == adapter
  end

  test "legacy strings and atoms reach Assent as atoms without the deprecated override" do
    strategy = Info.strategy!(Example.User, :oidc)
    methods = ~w(client_secret_basic client_secret_post client_secret_jwt private_key_jwt none)a

    for method <- methods, value <- [method, Atom.to_string(method)] do
      config = request_config(%{strategy | client_authentication_method: value})
      assert config[:client_authentication_method] == method
      refute Keyword.has_key?(config, :auth_method)
    end
  end

  test "OAuth2 auth_method remains supported without overriding the OIDC method" do
    oauth2 = Info.strategy!(Example.User, :oauth2)

    assert request_config(%{oauth2 | auth_method: :client_secret_basic})[
             :client_authentication_method
           ] == :client_secret_basic

    oidc = Info.strategy!(Example.User, :oidc)

    assert request_config(%{oidc | auth_method: :client_secret_post})[
             :client_authentication_method
           ] == :client_secret_basic
  end

  test "GitHub preserves the public auth_method override" do
    strategy = Info.strategy!(Example.User, :github)
    assert strategy.client_authentication_method == nil
    assert strategy.auth_method == :client_secret_post

    for method <- [:client_secret_basic, :private_key_jwt] do
      config = request_config(%{strategy | auth_method: method})
      assert config[:client_authentication_method] == method
      refute Keyword.has_key?(config, :auth_method)
    end
  end

  test "private_key_jwt requires a key for both the string and atom spelling" do
    strategy = Info.strategy!(Example.User, :oidc)

    for method <- [:private_key_jwt, "private_key_jwt"] do
      strategy = %{
        strategy
        | client_authentication_method: method,
          private_key: nil,
          private_key_path: nil
      }

      assert {:error, %DslError{}} = Verifier.verify(strategy, Example.User.spark_dsl_config())
    end
  end

  test "provider defaults compile with Assent 0.4's atom client authentication methods" do
    google = Info.strategy!(Example.UserWithOauth2Email, :google)
    microsoft = Info.strategy!(Example.User, :microsoft)
    assert google.client_authentication_method == :client_secret_post
    assert microsoft.client_authentication_method == :client_secret_post
    assert microsoft.openid_configuration == nil
  end

  test "OAuth2 callback uses Req, sends Basic credentials, and registers the user" do
    stub_provider()
    strategy = provider_strategy(:oauth2)
    conn = callback(strategy)
    assert {:ok, %Example.User{}} = conn.private[:authentication_result]
    assert_received {:token_request, [authorization], body}

    assert authorization ==
             "Basic " <>
               Base.encode64(
                 URI.encode_www_form(@client_id) <> ":" <> URI.encode_www_form(@secret)
               )

    assert URI.decode_query(body)["grant_type"] == "authorization_code"
    refute Map.has_key?(URI.decode_query(body), "client_secret")
    refute get_session(conn, "user/oauth2")
  end

  test "an error callback with a mismatched state fails before exchanging a token" do
    stub_provider()
    strategy = provider_strategy(:oauth2)
    conn = callback(strategy, %{"error" => "access_denied", "state" => "wrong"})
    assert {:error, %CallbackCSRFError{}} = conn.private[:authentication_result]
    refute_received {:token_request, _, _}
    refute get_session(conn, "user/oauth2")
  end

  test "OIDC callback validates the ID token nonce through Req and registers the user" do
    stub_provider()
    conn = callback(provider_strategy(:oidc))
    assert {:ok, %Example.User{}} = conn.private[:authentication_result]
    assert_received {:token_request, ["Basic " <> _], _}
  end

  test "OIDC rejects an ID token with the wrong nonce" do
    stub_provider(nonce: "wrong")
    conn = callback(provider_strategy(:oidc))
    assert {:error, %OIDC.InvalidIDTokenError{}} = conn.private[:authentication_result]
  end

  test "OIDC rejects discovery whose issuer differs from the configured base URL" do
    stub_provider(discovery_issuer: "https://other.example")
    conn = callback(provider_strategy(:oidc))

    assert {:error, %OIDC.InvalidOpenIDConfigurationError{}} =
             conn.private[:authentication_result]

    refute_received {:token_request, _, _}
  end

  test "Microsoft common authority validates the tenant-specific issuer" do
    stub_provider(microsoft: true)
    conn = callback(provider_strategy(:microsoft))
    assert {:ok, %Example.User{}} = conn.private[:authentication_result]
    assert_received {:discovery, "/#{@tenant}/v2.0/.well-known/openid-configuration"}
    assert_received {:token_request, _, body}
    assert URI.decode_query(body)["code_verifier"] == "code-verifier"
  end

  test "Microsoft rejects an invalid tenant claim before tenant discovery" do
    stub_provider(microsoft: true, tenant: "not-a-tenant")
    conn = callback(provider_strategy(:microsoft))
    assert {:error, %OIDC.InvalidIDTokenError{}} = conn.private[:authentication_result]
    refute_received {:discovery, _}
  end

  test "Microsoft base_url still restricts authentication to the configured tenant" do
    strategy = %{
      provider_strategy(:microsoft)
      | base_url: "https://login.microsoftonline.com/#{@tenant}/v2.0"
    }

    stub_provider(
      microsoft: true,
      token_issuer: "https://login.microsoftonline.com/00000000-0000-0000-0000-000000000002/v2.0"
    )

    conn = callback(strategy)
    assert {:error, %OIDC.InvalidIDTokenError{}} = conn.private[:authentication_result]
  end

  test "Microsoft tenant domains fail closed with a UUID migration hint" do
    strategy = %{
      provider_strategy(:microsoft)
      | base_url: "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0"
    }

    stub_provider(microsoft: true)
    request = conn(:get, "/") |> SessionPipeline.call([]) |> Plug.request(strategy)
    callback = callback(strategy)

    for conn <- [request, callback] do
      assert {:error, %ArgumentError{message: message}} = conn.private[:authentication_result]
      assert message =~ "directory UUID"
    end

    refute_received {:discovery, _}
    refute_received {:token_request, _, _}
  end

  test "Microsoft base_url is canonicalized, and B2C policy paths are rejected" do
    assert {:ok, "https://login.microsoftonline.com/abcdef01-0000-0000-0000-000000000001/v2.0"} =
             AzureADMultitenant.canonical_base_url(
               "https://login.microsoftonline.com/ABCDEF01-0000-0000-0000-000000000001"
             )

    assert {:error, %ArgumentError{message: message}} =
             AzureADMultitenant.canonical_base_url(
               "https://contoso.b2clogin.com/#{@tenant}/B2C_1_signin/v2.0"
             )

    assert message =~ "oidc strategy"
  end

  test "a literal Microsoft tenant domain is rejected at compile time" do
    strategy = %{
      provider_strategy(:microsoft)
      | base_url: "https://login.microsoftonline.com/contoso.onmicrosoft.com/v2.0"
    }

    assert {:error, %DslError{message: message}} =
             Microsoft.verify(
               strategy,
               Example.User.spark_dsl_config()
             )

    assert message =~ "directory UUID"
  end

  for {label, path} <- [{"without /v2.0", ""}, {"with a trailing slash", "/v2.0/"}] do
    test "a Microsoft tenant base_url #{label} still matches the issuer" do
      stub_provider(microsoft: true)
      base_url = "https://login.microsoftonline.com/#{@tenant}#{unquote(path)}"
      conn = callback(%{provider_strategy(:microsoft) | base_url: base_url})
      assert {:ok, %Example.User{}} = conn.private[:authentication_result]
      assert_received {:discovery, "/#{@tenant}/v2.0/.well-known/openid-configuration"}
    end
  end

  test "Auth0 accepts a base_url without the trailing slash of its issuer" do
    stub_provider(discovery_issuer: @issuer <> "/")

    conn =
      conn(:get, "/") |> SessionPipeline.call([]) |> Plug.request(provider_strategy(:auth0))

    assert conn.status == 302
    assert_received {:discovery, "/.well-known/openid-configuration"}
  end

  test "other OIDC strategies still require base_url to match the issuer exactly" do
    stub_provider(discovery_issuer: @issuer <> "/")

    conn =
      conn(:get, "/") |> SessionPipeline.call([]) |> Plug.request(provider_strategy(:oidc))

    assert {:error, %OIDC.InvalidOpenIDConfigurationError{}} =
             conn.private[:authentication_result]
  end

  defp request_config(strategy) do
    strategy = %{
      strategy
      | assent_strategy: CaptureConfig,
        base_url: @issuer,
        client_id: @client_id,
        client_secret: @secret,
        redirect_uri: "http://localhost:4000/auth"
    }

    conn(:get, "/") |> SessionPipeline.call([]) |> Plug.request(strategy)
    assert_received {:config, config}
    config
  end

  defp provider_strategy(name) do
    strategy = Info.strategy!(Example.User, name)

    %{
      strategy
      | client_id: @client_id,
        client_secret: @secret,
        base_url:
          if(name == :microsoft,
            do: "https://login.microsoftonline.com/common/v2.0",
            else: @issuer
          ),
        redirect_uri: "http://localhost:4000/auth",
        client_authentication_method: :client_secret_basic,
        id_token_signed_response_alg: "HS256",
        nonce: "nonce",
        token_url: if(name == :oauth2, do: @issuer <> "/token", else: nil),
        user_url: if(name == :oauth2, do: @issuer <> "/userinfo", else: nil)
    }
  end

  defp callback(strategy, params \\ %{"code" => "code", "state" => "state"}) do
    conn(:get, "/callback", params)
    |> SessionPipeline.call([])
    |> put_session("user/#{strategy.name}", %{
      state: "state",
      nonce: "nonce",
      code_verifier: "code-verifier"
    })
    |> Plug.callback(strategy)
  end

  defp stub_provider(opts \\ []) do
    Application.put_env(
      :ash_authentication,
      :http_adapter,
      {Assent.HTTPAdapter.Req, plug: {Req.Test, __MODULE__}}
    )

    issuer =
      if opts[:microsoft], do: "https://login.microsoftonline.com/#{@tenant}/v2.0", else: @issuer

    Req.Test.stub(__MODULE__, &provider_response(&1, issuer, opts))
  end

  defp provider_response(%{method: "GET", request_path: path} = conn, issuer, opts) do
    if String.ends_with?(path, "/.well-known/openid-configuration") do
      send(self(), {:discovery, path})

      Req.Test.json(conn, %{
        "issuer" => opts[:discovery_issuer] || issuer,
        "authorization_endpoint" => issuer <> "/authorize",
        "token_endpoint" => issuer <> "/token",
        "userinfo_endpoint" => issuer <> "/userinfo",
        "id_token_signing_alg_values_supported" => ["HS256"]
      })
    else
      userinfo_response(conn, issuer)
    end
  end

  defp provider_response(%{method: "POST"} = conn, issuer, opts) do
    {:ok, body, conn} = read_body(conn)
    send(self(), {:token_request, get_req_header(conn, "authorization"), body})

    claims = %{
      "sub" => "subject",
      "nickname" => "marty",
      "iss" => opts[:token_issuer] || issuer,
      "aud" => @client_id,
      "iat" => System.system_time(:second),
      "exp" => System.system_time(:second) + 300,
      "nonce" => opts[:nonce] || "nonce",
      "tid" => opts[:tenant] || @tenant
    }

    Req.Test.json(conn, %{
      "access_token" => "access",
      "token_type" => "Bearer",
      "id_token" => jwt(claims)
    })
  end

  defp userinfo_response(conn, issuer) do
    Req.Test.json(conn, %{
      "sub" => "subject",
      "nickname" => "marty",
      "iss" => issuer,
      "aud" => @client_id
    })
  end

  defp jwt(claims) do
    {:ok, token, _claims} = Joken.encode_and_sign(claims, Joken.Signer.create("HS256", @secret))
    token
  end
end
