# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Plug.DispatcherTest do
  @moduledoc false
  use ExUnit.Case, async: false
  alias AshAuthentication.Plug.Dispatcher

  import Plug.Test, only: [conn: 3, put_peer_data: 2]

  describe "request context" do
    setup do
      [conn: conn(:post, "/auth/user/password/sign_in_with_token ", %{})]
    end

    test "preserves existing context", %{conn: conn} do
      context =
        conn
        |> Ash.PlugHelpers.set_context(%{existing: "context"})
        |> dispatch()
        |> Ash.PlugHelpers.get_context()

      assert context.existing == "context"
      assert Map.has_key?(context, :ash_authentication_request)
    end

    test "formats conn's remote_ip over peer_data", %{conn: conn} do
      context =
        conn
        |> Map.put(:remote_ip, {203, 0, 113, 56})
        |> put_peer_data(%{address: {192, 0, 2, 34}, port: 40_000})
        |> dispatch()
        |> Ash.PlugHelpers.get_context()

      assert context.ash_authentication_request.remote_ip == "203.0.113.56"
    end
  end

  defp dispatch(conn) do
    Dispatcher.call(
      conn,
      {:sign_in_with_token, AshAuthentication.Info.strategy!(Example.User, :password),
       AshAuthentication.Plug.Defaults}
    )
  end
end
