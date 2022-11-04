defmodule AshAuthentication.Plug.HelpersTest do
  @moduledoc false
  use AshAuthentication.DataCase, async: true
  alias AshAuthentication.{Jwt, Plug.Helpers, SessionPipeline}
  import Plug.Test, only: [conn: 3]
  alias Plug.Conn

  setup do
    conn =
      :get
      |> conn("/", %{})
      |> SessionPipeline.call([])

    {:ok, conn: conn}
  end

  describe "store_in_session/2" do
    test "it stores the user in the session", %{conn: conn} do
      user = build_user()
      subject = AshAuthentication.resource_to_subject(user)

      conn =
        conn
        |> Helpers.store_in_session(user)

      assert conn.private.plug_session["user_with_username"] == subject
    end
  end

  describe "load_subjects/2" do
    test "it loads the subjects listed" do
      user = build_user()
      subject = AshAuthentication.resource_to_subject(user)

      rx_users = Helpers.load_subjects([subject], :ash_authentication)

      assert rx_users[:current_user_with_username].id == user.id
    end
  end

  describe "retrieve_from_session/2" do
    test "it loads any subjects stored in the session", %{conn: conn} do
      user = build_user()
      subject = AshAuthentication.resource_to_subject(user)

      conn =
        conn
        |> Conn.put_session("user_with_username", subject)
        |> Helpers.retrieve_from_session(:ash_authentication)

      assert conn.assigns.current_user_with_username.id == user.id
    end
  end

  describe "retrieve_from_bearer/2" do
    test "it loads any subjects from authorization headers", %{conn: conn} do
      user = build_user()

      conn =
        conn
        |> Conn.put_req_header("authorization", "Bearer #{user.__metadata__.token}")
        |> Helpers.retrieve_from_bearer(:ash_authentication)

      assert conn.assigns.current_user_with_username.id == user.id
    end
  end

  describe "revoke_bearer_tokens/2" do
    test "it revokes any tokens in the authorization headers", %{conn: conn} do
      user = build_user()

      {:ok, %{"jti" => jti}} =
        user.__metadata__.token
        |> Jwt.peek()

      conn
      |> Conn.put_req_header("authorization", "Bearer #{user.__metadata__.token}")
      |> Helpers.revoke_bearer_tokens(:ash_authentication)

      assert AshAuthentication.TokenRevocation.revoked?(user.__struct__, jti)
    end
  end

  describe "set_actor/2" do
    alias Ash.PlugHelpers

    test "it sets the actor when there is a `current_` resource in the assigns", %{conn: conn} do
      user = build_user()

      conn =
        conn
        |> Conn.assign(:current_user_with_username, user)
        |> Helpers.set_actor(:user_with_username)

      assert PlugHelpers.get_actor(conn) == user
    end

    test "it sets the actor to `nil` otherwise", %{conn: conn} do
      conn =
        conn
        |> Helpers.set_actor(:user_with_username)

      refute PlugHelpers.get_actor(conn)
    end
  end

  describe "private_store/2" do
    test "it stores the authentication result in the conn's private", %{conn: conn} do
      user = build_user()

      conn =
        conn
        |> Conn.put_private(:authenticator, %{resource: user.__struct__})
        |> Helpers.private_store({:success, user})

      assert conn.private.authentication_result == {:success, user}
    end
  end
end
