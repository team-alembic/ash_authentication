# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Plug.DispatcherTest do
  @moduledoc false
  use ExUnit.Case, async: false
  alias AshAuthentication.Plug.Dispatcher

  import Plug.Test, only: [conn: 3, put_peer_data: 2]

  setup do
    original_request_remote_ip_source =
      Application.get_env(:ash_authentication, :request_remote_ip_source)

    on_exit(fn ->
      Application.put_env(
        :ash_authentication,
        :request_remote_ip_source,
        original_request_remote_ip_source
      )
    end)

    :ok
  end

  describe "request context" do
    test "preserves existing context" do
      context =
        conn_with_remote_ips()
        |> Ash.PlugHelpers.set_context(%{existing: "context"})
        |> dispatch()
        |> Ash.PlugHelpers.get_context()

      assert context.existing == "context"
      assert Map.has_key?(context, :ash_authentication_request)
    end

    test "defaults to peer data for remote_ip" do
      Application.delete_env(:ash_authentication, :request_remote_ip_source)

      context =
        conn_with_remote_ips()
        |> dispatch()
        |> Ash.PlugHelpers.get_context()

      assert context.ash_authentication_request.remote_ip == "192.0.2.34"
    end

    test "uses conn.remote_ip when request_remote_ip_source is configured as :conn" do
      Application.put_env(:ash_authentication, :request_remote_ip_source, :conn)

      context =
        conn_with_remote_ips()
        |> dispatch()
        |> Ash.PlugHelpers.get_context()

      assert context.ash_authentication_request.remote_ip == "203.0.113.56"
    end
  end

  defp conn_with_remote_ips do
    :post
    |> conn("/auth/user/password/sign_in_with_token ", %{})
    |> Map.put(:remote_ip, {203, 0, 113, 56})
    |> put_peer_data(%{address: {192, 0, 2, 34}, port: 40_000})
  end

  defp dispatch(conn) do
    Dispatcher.call(
      conn,
      {:sign_in_with_token, AshAuthentication.Info.strategy!(Example.User, :password),
       AshAuthentication.Plug.Defaults}
    )
  end
end
