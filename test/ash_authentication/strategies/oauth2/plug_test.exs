# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.PlugTest do
  @moduledoc false
  use DataCase, async: true
  import Plug.Conn
  import Plug.Test

  alias AshAuthentication.{Info, Strategy.OAuth2.Plug}

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
end
