# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.PlugTest do
  @moduledoc false
  use DataCase, async: true
  import Plug.Conn
  import Plug.Test

  alias AshAuthentication.{Info, Strategy.OAuth2.Plug}

  defmodule ConfigCapturingAssentStrategy do
    @moduledoc false
    @behaviour Assent.Strategy

    @impl true
    def authorize_url(config) do
      send(self(), {:config, config})
      {:ok, %{session_params: %{state: "s"}, url: "https://example.com/authorize"}}
    end

    @impl true
    def callback(_config, _params), do: {:error, :not_implemented}
  end

  defmodule SucceedingAssentStrategy do
    @moduledoc false
    @behaviour Assent.Strategy

    @impl true
    def authorize_url(_config), do: {:error, :not_implemented}

    @impl true
    def callback(_config, _params) do
      {:ok,
       %{
         user: %{"sub" => "succeeding-assent-strategy", "nickname" => "marty"},
         token: %{"access_token" => "pretend access token"}
       }}
    end
  end

  describe "request/2" do
    test "it builds the redirect url and redirects the user" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)

      assert conn =
               :get
               |> conn("/", %{})
               |> SessionPipeline.call([])
               |> Plug.request(strategy)

      assert conn.status == 302
      assert {"location", location} = Enum.find(conn.resp_headers, &(elem(&1, 0) == "location"))
      assert String.starts_with?(location, "https://example.com/authorize?")
      session = get_session(conn, "user/oauth2")
      assert session.state =~ ~r/.+/
    end
  end

  describe "callback/2 with no session (cross-site form_post)" do
    setup do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)
      {:ok, strategy: strategy}
    end

    test "a POST with no session renders an interstitial that re-POSTs same-origin", %{
      strategy: strategy
    } do
      conn =
        :post
        |> conn("/user/oauth2/callback", %{"code" => "abc", "state" => "x<script>"})
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      assert conn.status == 200

      assert {"content-type", "text/html" <> _} =
               Enum.find(conn.resp_headers, &(elem(&1, 0) == "content-type"))

      body = conn.resp_body
      assert body =~ ~s(<form method="post" action="/user/oauth2/callback">)
      assert body =~ ~s(name="code" value="abc")
      # values are HTML-escaped
      assert body =~ ~s(value="x&lt;script&gt;")
      refute body =~ "x<script>"
      # the loop guard marker is added
      assert body =~ ~s(name="_ash_authentication_reflected" value="1")

      # the interstitial must NOT rewrite the session cookie, or the fresh cookie
      # would clobber the real session and the same-origin re-POST would arrive
      # without it.
      assert conn.private[:plug_session_info] == :ignore
    end

    test "an already-reflected POST with no session fails closed rather than looping", %{
      strategy: strategy
    } do
      conn =
        :post
        |> conn("/user/oauth2/callback", %{
          "code" => "abc",
          "state" => "xyz",
          "_ash_authentication_reflected" => "1"
        })
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      refute conn.status == 200
      assert conn.private[:authentication_result] == {:error, nil}
    end

    test "a GET with no session does not render an interstitial", %{strategy: strategy} do
      conn =
        :get
        |> conn("/user/oauth2/callback", %{"code" => "abc"})
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      refute conn.status == 200
      assert conn.private[:authentication_result] == {:error, nil}
    end
  end

  describe "callback/2 with no session (IdP-initiated)" do
    test "a stateless GET fails closed when idp_initiated_login? is disabled" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)

      conn =
        :get
        |> conn("/user/oauth2/callback", %{"code" => "abc"})
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      # No request phase ran (no stored session), and the strategy hasn't opted
      # into IdP-initiated handling, so we must not complete authentication.
      assert conn.private[:authentication_result] == {:error, nil}
      refute conn.status == 302
    end

    test "a stateless GET restarts the request phase when idp_initiated_login? is enabled" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2_idp_initiated)

      conn =
        :get
        |> conn("/user/oauth2_idp_initiated/callback", %{"code" => "abc"})
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      # The stateless callback is treated as a trigger: discard the inbound
      # response and redirect into the request phase (OIDC Core §4), which mints
      # a fresh `state` in the session for later verification.
      assert conn.status == 302
      assert {"location", location} = Enum.find(conn.resp_headers, &(elem(&1, 0) == "location"))
      assert String.starts_with?(location, "https://example.com/authorize?")

      session = get_session(conn, "user/oauth2_idp_initiated")
      assert session.state =~ ~r/.+/

      # We did not complete authentication from the inbound `code`.
      refute match?({:ok, _}, conn.private[:authentication_result])
    end

    test "a stateless POST still takes the interstitial, not the restart, when idp_initiated_login? is enabled" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2_idp_initiated)

      conn =
        :post
        |> conn("/user/oauth2_idp_initiated/callback", %{"code" => "abc"})
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      # `idp_initiated_login?` restarts on GET only. A stateless POST is the
      # cross-site form_post case (Sign in with Apple), so it must render the
      # same-origin re-POST interstitial — the request-phase restart must not
      # pre-empt it.
      assert conn.status == 200
      assert conn.resp_body =~ ~s(name="_ash_authentication_reflected" value="1")
      refute conn.status == 302
    end

    test "a stateless GET carrying a `state` fails closed rather than restarting again" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2_idp_initiated)

      conn =
        :get
        |> conn("/user/oauth2_idp_initiated/callback", %{"code" => "abc", "state" => "xyz"})
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      # A genuine IdP-initiated launch carries no `state`. This one does, so a
      # request phase already ran and its session should have been present — it
      # could not be persisted, or was stripped. Restarting would mint another
      # `state` into a session that will be lost again and loop the browser, so
      # fail closed.
      assert conn.private[:authentication_result] == {:error, nil}
      refute conn.status == 302
      refute conn.status == 200
    end
  end

  describe "callback/2 session cleanup" do
    setup do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)
      {:ok, strategy: strategy}
    end

    test "a failed callback clears the session holding `session_params`", %{strategy: strategy} do
      conn =
        :get
        |> conn("/user/oauth2/callback", %{"error" => "access_denied"})
        |> SessionPipeline.call([])
        |> put_session("user/oauth2", %{state: "pretend state"})
        |> Plug.callback(strategy)

      assert {:error, _reason} = conn.private[:authentication_result]

      # The `state` is single-use. Leaving it in the session lets a later
      # callback carrying it be replayed against this session.
      refute get_session(conn, "user/oauth2")
    end

    test "a successful callback clears the session holding `session_params`", %{
      strategy: strategy
    } do
      strategy = %{strategy | assent_strategy: SucceedingAssentStrategy}

      conn =
        :get
        |> conn("/user/oauth2/callback", %{"code" => "abc", "state" => "pretend state"})
        |> SessionPipeline.call([])
        |> put_session("user/oauth2", %{state: "pretend state"})
        |> Plug.callback(strategy)

      assert {:ok, _user} = conn.private[:authentication_result]
      refute get_session(conn, "user/oauth2")
    end
  end

  describe "client assertion signing algorithm" do
    setup do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)
      {:ok, strategy: %{strategy | assent_strategy: ConfigCapturingAssentStrategy}}
    end

    test "the config carries no `:jwt_algorithm`, so Assent applies its per-method default", %{
      strategy: strategy
    } do
      :get
      |> conn("/", %{})
      |> SessionPipeline.call([])
      |> Plug.request(strategy)

      assert_received {:config, config}
      refute Keyword.has_key?(config, :jwt_algorithm)
    end

    test "a `private_key_jwt` strategy does not inherit the token signing algorithm", %{
      strategy: strategy
    } do
      strategy = %{strategy | auth_method: :private_key_jwt}

      {:ok, signing_algorithm} =
        AshAuthentication.Info.authentication_tokens_signing_algorithm(Example.User)

      assert signing_algorithm == "HS256"

      :get
      |> conn("/", %{})
      |> SessionPipeline.call([])
      |> Plug.request(strategy)

      assert_received {:config, config}

      # Assent defaults `private_key_jwt` to RS256. Passing our own HS256 here
      # would HMAC the PEM bytes instead of signing with the private key.
      refute Keyword.has_key?(config, :jwt_algorithm)
    end
  end
end
