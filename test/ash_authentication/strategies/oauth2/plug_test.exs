# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.PlugTest do
  @moduledoc false
  use DataCase, async: true
  import Plug.Conn
  import Plug.Test

  alias AshAuthentication.{Info, Strategy.OAuth2.Plug}

  describe "callback/2" do
    test "it does not reject a callback that has no stored session params" do
      # IdP-initiated logins (the user launches from the provider rather than
      # starting at request/2) arrive with no session params stored. The
      # callback must not short-circuit to {:error, nil} in that case — it
      # should pass the (empty) session params through to the strategy, which
      # then proceeds with the exchange. A missing `code` here fails *later*,
      # in the strategy, with a non-nil error — proving the empty-session
      # guard no longer rejects the request outright.
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)

      conn =
        :get
        |> conn("/", %{})
        |> SessionPipeline.call([])
        |> Plug.callback(strategy)

      assert {:error, reason} = conn.private.authentication_result
      refute is_nil(reason)
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
end
