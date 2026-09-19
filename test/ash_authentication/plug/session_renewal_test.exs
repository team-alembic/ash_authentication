# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Plug.SessionRenewalTest do
  @moduledoc """
  The session identifier must not survive the move from anonymous to
  authenticated. These tests run against an ETS session store, because the
  cookie store has no identifier to rotate.
  """
  use DataCase, async: true
  alias AshAuthentication.Plug.Helpers
  alias Plug.Conn
  import Plug.Test, only: [conn: 3, put_req_cookie: 3]

  setup do
    store = ServerSideSessionPipeline.new_store()

    {:ok, store: store}
  end

  describe "store_in_session/2" do
    test "it issues a new session identifier", %{store: store} do
      {anonymous_id, _} = anonymous_session(store)

      authenticated =
        store
        |> request(anonymous_id)
        |> Helpers.store_in_session(build_user())

      authenticated_id = ServerSideSessionPipeline.sent_session_id(authenticated)

      assert is_binary(authenticated_id)
      refute authenticated_id == anonymous_id
    end

    test "it drops the anonymous session from the store", %{store: store} do
      {anonymous_id, _} = anonymous_session(store)

      assert [_] = :ets.lookup(store, anonymous_id)

      store
      |> request(anonymous_id)
      |> Helpers.store_in_session(build_user())
      |> ServerSideSessionPipeline.sent_session_id()

      assert [] = :ets.lookup(store, anonymous_id)
    end

    test "it carries the session contents across the renewal", %{store: store} do
      # `Phoenix.Controller.put_flash/3` stores the flash under this session
      # key, so a plain session write reproduces what the flash relies on.
      {anonymous_id, _} =
        anonymous_session(store, %{
          "return_to" => "/dashboard",
          "phoenix_flash" => %{"info" => "Welcome back"}
        })

      authenticated =
        store
        |> request(anonymous_id)
        |> Helpers.store_in_session(build_user())

      assert Conn.get_session(authenticated, "return_to") == "/dashboard"
      assert Conn.get_session(authenticated, "phoenix_flash") == %{"info" => "Welcome back"}

      authenticated_id = ServerSideSessionPipeline.sent_session_id(authenticated)
      refute authenticated_id == anonymous_id

      assert [{^authenticated_id, contents, _}] = :ets.lookup(store, authenticated_id)
      assert contents["return_to"] == "/dashboard"
      assert contents["user"]
    end

    test "it renews for a user whose session holds the token", %{store: store} do
      {anonymous_id, _} = anonymous_session(store)

      authenticated =
        store
        |> request(anonymous_id)
        |> Helpers.store_in_session(build_user_with_token_required())

      assert Conn.get_session(authenticated, "user_with_token_required_token")
      refute ServerSideSessionPipeline.sent_session_id(authenticated) == anonymous_id
    end
  end

  describe "sign_in_using_remember_me/3" do
    test "auto-login issues a new session identifier", %{store: store} do
      user = build_user_with_remember_me()
      {:ok, remember_me_token} = generate_remember_me_token(user)

      {anonymous_id, _} = anonymous_session(store, %{"return_to" => "/dashboard"})

      authenticated =
        store
        |> request(anonymous_id, %{"remember_me" => remember_me_token})
        |> Helpers.sign_in_using_remember_me(:ash_authentication)

      assert Conn.get_session(authenticated, "user_with_remember_me_token")
      assert Conn.get_session(authenticated, "return_to") == "/dashboard"
      refute ServerSideSessionPipeline.sent_session_id(authenticated) == anonymous_id
    end

    test "it leaves the session identifier alone when there is no cookie", %{store: store} do
      {anonymous_id, _} = anonymous_session(store, %{"return_to" => "/dashboard"})

      untouched =
        store
        |> request(anonymous_id)
        |> Helpers.sign_in_using_remember_me(:ash_authentication)
        |> Conn.put_session("touched", true)

      assert ServerSideSessionPipeline.sent_session_id(untouched) == anonymous_id
    end

    test "a second request does not renew again", %{store: store} do
      user = build_user_with_remember_me_token_optional()
      {:ok, remember_me_token} = generate_remember_me_token(user)

      {anonymous_id, _} = anonymous_session(store)

      first =
        store
        |> request(anonymous_id, %{"remember_me_token_optional" => remember_me_token})
        |> Helpers.sign_in_using_remember_me(:ash_authentication)

      first_id = ServerSideSessionPipeline.sent_session_id(first)
      refute first_id == anonymous_id

      second =
        store
        |> request(first_id, %{"remember_me_token_optional" => remember_me_token})
        |> Helpers.sign_in_using_remember_me(:ash_authentication)
        |> Conn.put_session("touched", true)

      assert ServerSideSessionPipeline.sent_session_id(second) == first_id
    end
  end

  defp anonymous_session(store, contents \\ %{"visited" => true}) do
    conn =
      :get
      |> conn("/", %{})
      |> ServerSideSessionPipeline.call(store)

    conn =
      Enum.reduce(contents, conn, fn {key, value}, conn ->
        Conn.put_session(conn, key, value)
      end)

    {ServerSideSessionPipeline.sent_session_id(conn), conn}
  end

  defp request(store, session_id, cookies \\ %{}) do
    :get
    |> conn("/", %{})
    |> put_req_cookie(ServerSideSessionPipeline.cookie_key(), session_id)
    |> then(fn conn ->
      Enum.reduce(cookies, conn, fn {name, value}, conn ->
        put_req_cookie(conn, name, value)
      end)
    end)
    |> ServerSideSessionPipeline.call(store)
  end
end
