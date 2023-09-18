defmodule AshAuthentication.Plug.HelpersTest do
  @moduledoc false
  use DataCase, async: true
  alias AshAuthentication.{Info, Jwt, Plug.Helpers, Strategy.Password, TokenResource}
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
    test "when token presence is not required it stores the user in the session", %{conn: conn} do
      user = build_user()
      subject = AshAuthentication.user_to_subject(user)

      conn =
        conn
        |> Helpers.store_in_session(user)

      assert conn.private.plug_session["user"] == subject
    end

    test "when token presence is required it stores the token in the session", %{conn: conn} do
      user = build_user_with_token_required()

      conn =
        conn
        |> Helpers.store_in_session(user)

      assert conn.private.plug_session["user_with_token_required_token"] ==
               user.__metadata__.token
    end
  end

  describe "load_subjects/2" do
    test "it loads the subjects listed" do
      user = build_user()
      subject = AshAuthentication.user_to_subject(user)

      rx_users = Helpers.load_subjects([subject], :ash_authentication)

      assert rx_users[:current_user].id == user.id
    end
  end

  describe "retrieve_from_session/2" do
    test "when token presence is not required it loads any subjects stored in the session", %{
      conn: conn
    } do
      user = build_user()
      subject = AshAuthentication.user_to_subject(user)

      conn =
        conn
        |> Conn.put_session("user", subject)
        |> Helpers.retrieve_from_session(:ash_authentication)

      assert conn.assigns.current_user.id == user.id
    end

    test "when token presence is required and the token is present in the token resource it loads the token's subject",
         %{conn: conn} do
      user = build_user_with_token_required()

      conn =
        conn
        |> Conn.put_session("user_with_token_required_token", user.__metadata__.token)
        |> Helpers.retrieve_from_session(:ash_authentication)

      assert conn.assigns.current_user_with_token_required.id == user.id
    end

    test "when token presense is required and the token is not present in the token resource it doesn't load the token's subject",
         %{conn: conn} do
      user = build_user_with_token_required()
      {:ok, %{"jti" => jti}} = Jwt.peek(user.__metadata__.token)

      import Ecto.Query

      Example.Repo.delete_all(from(t in Example.Token, where: t.jti == ^jti))

      conn =
        conn
        |> Conn.put_session("user_with_token_required_token", user.__metadata__.token)
        |> Helpers.retrieve_from_session(:ash_authentication)

      refute conn.assigns.current_user_with_token_required
    end

    test "when token presense is requried and the token has been revoked it doesn't load the token's subject",
         %{conn: conn} do
      user = build_user_with_token_required()

      :ok = TokenResource.revoke(Example.Token, user.__metadata__.token)

      conn =
        conn
        |> Conn.put_session("user_with_token_required_token", user.__metadata__.token)
        |> Helpers.retrieve_from_session(:ash_authentication)

      refute conn.assigns.current_user_with_token_required
    end

    test "when the token is for another purpose it can't be used for sign in", %{conn: conn} do
      user = build_user_with_token_required()

      strategy = Info.strategy!(user.__struct__, :password)
      {:ok, reset_token} = Password.reset_token_for(strategy, user)

      conn =
        conn
        |> Conn.put_session("user_with_token_required_token", reset_token)
        |> Helpers.retrieve_from_session(:ash_authentication)

      refute conn.assigns.current_user_with_token_required
    end
  end

  describe "retrieve_from_bearer/2" do
    test "when token presense is not required it loads any subjects from authorization header(s)",
         %{conn: conn} do
      user = build_user()

      conn =
        conn
        |> Conn.put_req_header("authorization", "Bearer #{user.__metadata__.token}")
        |> Helpers.retrieve_from_bearer(:ash_authentication)

      assert conn.assigns.current_user.id == user.id
    end

    test "when token presense is required and the token is present in the database it loads the subjects from the authorization header(s)",
         %{conn: conn} do
      user = build_user_with_token_required()

      conn =
        conn
        |> Conn.put_req_header("authorization", "Bearer #{user.__metadata__.token}")
        |> Helpers.retrieve_from_bearer(:ash_authentication)

      assert conn.assigns.current_user_with_token_required.id == user.id

      assert {:ok, user_for_token} =
               AshAuthentication.subject_to_user(
                 conn.assigns.current_user_with_token_required_token_record.subject,
                 Example.UserWithTokenRequired
               )

      assert user_for_token.id == user.id
    end

    test "when token presense is required and the token is not present in the token resource it doesn't load the subjects from the authorization header(s)",
         %{conn: conn} do
      user = build_user_with_token_required()
      {:ok, %{"jti" => jti}} = Jwt.peek(user.__metadata__.token)

      import Ecto.Query

      Example.Repo.delete_all(from(t in Example.Token, where: t.jti == ^jti))

      conn =
        conn
        |> Conn.put_req_header("authorization", "Bearer #{user.__metadata__.token}")
        |> Helpers.retrieve_from_bearer(:ash_authentication)

      refute is_map_key(conn.assigns, :current_user_with_token_required)
      refute is_map_key(conn.assigns, :current_user_with_token_required_token_record)
    end

    test "when token presense is required and the token has been revoked it doesn't lkoad the subjects from the authorization header(s)",
         %{conn: conn} do
      user = build_user_with_token_required()

      :ok = TokenResource.revoke(Example.Token, user.__metadata__.token)

      conn =
        conn
        |> Conn.put_req_header("authorization", "Bearer #{user.__metadata__.token}")
        |> Helpers.retrieve_from_bearer(:ash_authentication)

      refute is_map_key(conn.assigns, :current_user_with_token_required)
    end

    test "when the token is for another purpose, it doesn't let them sign in", %{conn: conn} do
      user = build_user()

      strategy = Info.strategy!(user.__struct__, :password)
      {:ok, reset_token} = Password.reset_token_for(strategy, user)

      conn =
        conn
        |> Conn.put_req_header("authorization", "Bearer #{reset_token}")
        |> Helpers.retrieve_from_bearer(:ash_authentication)

      refute is_map_key(conn.assigns, :current_user_with_token_required)
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

      assert AshAuthentication.TokenResource.jti_revoked?(user.__struct__, jti)
    end
  end

  describe "set_actor/2" do
    alias Ash.PlugHelpers

    test "it sets the actor when there is a `current_` resource in the assigns", %{conn: conn} do
      user = build_user()

      conn =
        conn
        |> Conn.assign(:current_user, user)
        |> Helpers.set_actor(:user)

      assert PlugHelpers.get_actor(conn) == user
    end

    test "it sets the actor to `nil` otherwise", %{conn: conn} do
      conn =
        conn
        |> Helpers.set_actor(:user)

      refute PlugHelpers.get_actor(conn)
    end
  end

  describe "store_authentication_result/2" do
    test "it stores the authentication result in the conn's private", %{conn: conn} do
      user = build_user()

      conn =
        conn
        |> Conn.put_private(:authenticator, %{resource: user.__struct__})
        |> Helpers.store_authentication_result({:ok, user})

      assert conn.private.authentication_result == {:ok, user}
    end
  end
end
