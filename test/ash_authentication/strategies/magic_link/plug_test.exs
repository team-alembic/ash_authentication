# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.MagicLink.PlugTest do
  @moduledoc false
  use DataCase, async: true
  import Plug.Test

  alias AshAuthentication.{Info, Strategy.MagicLink.Plug}

  describe "accept/2" do
    test "it HTML-escapes the token into the rendered form" do
      {:ok, strategy} = Info.strategy(Example.User, :magic_link)

      payload = ~s|"><script>alert(1)</script>|

      conn =
        :get
        |> conn("/", %{"token" => payload})
        |> Plug.accept(strategy)

      assert conn.status == 200

      refute conn.resp_body =~ payload
      refute conn.resp_body =~ "<script>"

      assert conn.resp_body =~
               ~s|value="&quot;&gt;&lt;script&gt;alert(1)&lt;/script&gt;"|
    end
  end
end
