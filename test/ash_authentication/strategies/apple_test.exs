# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.AppleTest do
  @moduledoc false
  use DataCase, async: true
  import Plug.Conn
  import Plug.Test

  alias AshAuthentication.{Info, Strategy.OAuth2.Plug}
  alias Assent.Strategy.Apple

  describe "the apple entity" do
    setup do
      {:ok, strategy} = Info.strategy(Example.User, :apple)
      {:ok, strategy: strategy}
    end

    test "it builds with Assent's Apple defaults, `openid_default_scope: nil` included", %{
      strategy: strategy
    } do
      assert strategy.assent_strategy == Apple

      assert Keyword.fetch!(Apple.default_config([]), :openid_default_scope) ==
               nil

      assert strategy.openid_default_scope == nil
    end

    test "the request phase asks Apple for the `email` scope alone, with a form_post response",
         %{strategy: strategy} do
      conn =
        :get
        |> conn("/", %{})
        |> SessionPipeline.call([])
        |> Plug.request(strategy)

      assert conn.status == 302
      assert [location] = get_resp_header(conn, "location")

      assert %URI{host: "appleid.apple.com", path: "/auth/authorize", query: query} =
               URI.parse(location)

      assert %{"scope" => "email", "response_mode" => "form_post"} = URI.decode_query(query)
    end
  end
end
