# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Plug.DefaultsTest do
  @moduledoc false
  use DataCase, async: true
  alias AshAuthentication.{Plug.Defaults}
  import Plug.Test, only: [conn: 3]

  setup do
    conn =
      :get
      |> conn("/", %{})
      |> SessionPipeline.call([])

    {:ok, conn: conn}
  end

  describe "handle_success/3" do
    test "it returns 200 and a basic message", %{conn: conn} do
      user = build_user()

      conn =
        conn
        |> Defaults.handle_success({nil, nil}, user, user.__metadata__.token)

      assert conn.status == 200
      assert conn.resp_body =~ ~r/access granted/i
    end
  end

  describe "handle_failure/2" do
    test "it returns 401 and a basic message", %{conn: conn} do
      conn =
        conn
        |> Defaults.handle_failure({nil, nil}, :arbitrary_reason)

      assert conn.status == 401
      assert conn.resp_body =~ ~r/access denied/i
    end
  end
end
