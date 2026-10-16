# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.DynamicOidc.PlugTest do
  @moduledoc false
  use DataCase, async: true
  use Mimic

  import Plug.Test

  alias AshAuthentication.{Info, Strategy.DynamicOidc, Strategy.OAuth2}

  setup do
    connection =
      Ash.Seed.seed!(Example.OidcConnection, %{
        base_url: "https://idp.example.com",
        client_id: "client-id",
        client_secret: "client-secret"
      })

    %{connection: connection, strategy: Info.strategy!(Example.User, :sso)}
  end

  test "the request phase loads the connection through the resource's AshAuthentication bypass",
       %{connection: connection, strategy: strategy} do
    test_pid = self()

    stub(OAuth2.Plug, :request, fn conn, populated ->
      send(test_pid, {:populated, populated})
      conn
    end)

    conn(:get, "/")
    |> Ash.PlugHelpers.set_context(%{private: %{app: :value}})
    |> Map.put(:path_params, %{"connection_id" => to_string(connection.id)})
    |> init_test_session(%{})
    |> DynamicOidc.Plug.request(strategy)

    assert_received {:populated, populated}
    assert populated.base_url == "https://idp.example.com"
    assert populated.client_id == "client-id"
    assert populated.client_secret == "client-secret"
    assert populated.__connection_id__ == to_string(connection.id)
  end

  test "outside the strategy the connection is still subject to the resource's policies",
       %{connection: connection} do
    assert {:error, %Ash.Error.Forbidden{}} = Ash.get(Example.OidcConnection, connection.id)
  end
end
