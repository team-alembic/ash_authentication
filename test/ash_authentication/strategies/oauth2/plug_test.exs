# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.PlugTest do
  @moduledoc false
  use DataCase, async: true
  import Plug.Conn
  import Plug.Test

  alias AshAuthentication.{Info, Strategy.OAuth2.Plug}

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
end
