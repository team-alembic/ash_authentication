defmodule AshAuthentication.Plug.HelpersTest do
  @moduledoc false
  use DataCase, async: true
  alias AshAuthentication.{Info, Jwt, Plug.Helpers, Strategy.Password, TokenResource}
  import Plug.Test, only: [conn: 3, put_req_cookie: 3]
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

      jti =
        user.__metadata__.token
        |> AshAuthentication.Jwt.peek()
        |> elem(1)
        |> Map.fetch!("jti")

      assert conn.private.plug_session["user"] == jti <> ":" <> subject
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

  describe "assign_new_resources/4" do
    test "it assigns the users according to the callback", %{conn: conn} do
      user = build_user()

      conn =
        conn
        |> Helpers.store_in_session(user)

      socket = %{}

      session =
        %{"user" => Plug.Conn.get_session(conn, "user")}

      assign_new = &Map.put_new_lazy/3

      new_assigns =
        Helpers.assign_new_resources(socket, session, assign_new, otp_app: :ash_authentication)

      assert new_assigns[:current_user].id == user.id

      socket = %{current_user: :foo}

      new_assigns =
        Helpers.assign_new_resources(socket, session, assign_new, otp_app: :ash_authentication)

      assert new_assigns[:current_user] == :foo
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

  describe "retrieve_from_session/3" do
    test "when token presence is not required it loads any subjects stored in the session", %{
      conn: conn
    } do
      user = build_user()
      subject = AshAuthentication.user_to_subject(user)

      conn =
        conn
        |> Conn.put_session("user", "jti:" <> subject)
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

    test "with opts", %{conn: conn} do
      # without token
      user = build_user()
      subject = AshAuthentication.user_to_subject(user)

      conn0 =
        conn
        |> Conn.put_session("user", "jti:" <> subject)
        |> Helpers.retrieve_from_session(:ash_authentication, load: [:dummy_calc])

      assert conn0.assigns.current_user.dummy_calc == "dummy"

      # with token
      user_with_token = build_user_with_token_required()

      conn1 =
        conn
        |> Conn.put_session("user_with_token_required_token", user_with_token.__metadata__.token)
        |> Helpers.retrieve_from_session(:ash_authentication, load: [:dummy_calc])

      assert conn1.assigns.current_user_with_token_required.dummy_calc == "dummy"
    end
  end

  describe "retrieve_from_bearer/3" do
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

    test "with opts", %{conn: conn} do
      user = build_user()

      conn0 =
        conn
        |> Conn.put_req_header("authorization", "Bearer #{user.__metadata__.token}")
        |> Helpers.retrieve_from_bearer(:ash_authentication, load: [:dummy_calc])

      assert conn0.assigns.current_user.dummy_calc == "dummy"

      # with token
      user_with_token = build_user_with_token_required()

      conn1 =
        conn
        |> Conn.put_req_header("authorization", "Bearer #{user_with_token.__metadata__.token}")
        |> Helpers.retrieve_from_bearer(:ash_authentication, load: [:dummy_calc])

      assert conn1.assigns.current_user_with_token_required.dummy_calc == "dummy"
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

  describe "revoke_session_tokens/3" do
    test "when token presence is required and token is in session it revokes the token", %{
      conn: conn
    } do
      user = build_user_with_token_required()

      conn =
        conn
        |> Helpers.store_in_session(user)

      {:ok, %{"jti" => jti}} = Jwt.peek(user.__metadata__.token)

      refute AshAuthentication.TokenResource.jti_revoked?(Example.Token, jti)

      conn
      |> Helpers.revoke_session_tokens(:ash_authentication)

      assert AshAuthentication.TokenResource.jti_revoked?(Example.Token, jti)
    end

    test "when token presence is required and no token in session it handles gracefully", %{
      conn: conn
    } do
      conn
      |> Helpers.revoke_session_tokens(:ash_authentication)
    end

    test "when token presence is not required it properly revokes the token", %{conn: conn} do
      user = build_user()

      conn =
        conn
        |> Helpers.store_in_session(user)

      {:ok, %{"jti" => jti}} = Jwt.peek(user.__metadata__.token)

      refute AshAuthentication.TokenResource.jti_revoked?(Example.Token, jti)

      conn
      |> Helpers.revoke_session_tokens(:ash_authentication)

      assert AshAuthentication.TokenResource.jti_revoked?(Example.Token, jti)
    end

    test "when token presence is required and deleted token in session it still revokes successfully",
         %{
           conn: conn
         } do
      user = build_user_with_token_required()
      {:ok, %{"jti" => jti}} = Jwt.peek(user.__metadata__.token)

      # Remove the token from the database to simulate an invalid/expired token
      import Ecto.Query
      Example.Repo.delete_all(from(t in Example.Token, where: t.jti == ^jti))

      conn =
        conn
        |> Conn.put_session("user_with_token_required_token", user.__metadata__.token)

      # Even for deleted tokens, revocation should succeed by creating a revocation record
      conn
      |> Helpers.revoke_session_tokens(:ash_authentication)

      # Verify the token is now revoked
      assert AshAuthentication.TokenResource.jti_revoked?(Example.Token, jti)
    end

    test "when token presence is required and completely invalid token format in session it raises an error",
         %{
           conn: conn
         } do
      conn =
        conn
        |> Conn.put_session("user_with_token_required_token", "completely_invalid_token_format")

      # This should raise a MatchError because the implementation expects revoke to succeed
      assert_raise MatchError, fn ->
        conn
        |> Helpers.revoke_session_tokens(:ash_authentication)
      end
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

  describe "sign_in_using_remember_me/3" do
    test "when user is already signed in via session, it does nothing", %{conn: conn} do
      user = build_user()
      subject = AshAuthentication.user_to_subject(user)

      conn =
        conn
        |> Conn.put_session("user", "jti:" <> subject)
        |> Helpers.sign_in_using_remember_me(:ash_authentication)

      # Should not have any remember me cookies set
      assert conn.resp_cookies == %{}
      # Should not have any assigns set
      refute conn.private.plug_session["user_with_remember_me"]
    end

    test "when no remember me strategy is configured, it does nothing", %{conn: conn} do
      conn = Helpers.sign_in_using_remember_me(conn, :ash_authentication)

      # Should not have any remember me cookies set
      assert conn.resp_cookies == %{}
      # Should not have any assigns set
      refute conn.private.plug_session["user_with_remember_me"]
    end

    test "when remember me cookie is present and valid, it signs in the user" do
      # Create a user with remember me strategy
      user = build_user_with_remember_me()

      # Generate a remember me token
      {:ok, remember_me_token} = generate_remember_me_token(user)

      # Set the remember me cookie
      conn =
        :get
        |> conn("/", %{})
        |> put_req_cookie("ash_auth:remember_me", remember_me_token)
        |> SessionPipeline.call([])
        |> Helpers.sign_in_using_remember_me(:ash_authentication)

      # Should have the user_with_remember_me stored in session
      assert conn.private.plug_session["user_with_remember_me"]
    end

    test "when remember me cookie is present but invalid, it deletes the cookie" do
      # Set an invalid remember me cookie
      conn =
        :get
        |> conn("/", %{})
        |> put_req_cookie("ash_auth:remember_me", "invalid_token")
        |> SessionPipeline.call([])
        |> Helpers.sign_in_using_remember_me(:ash_authentication)

      # Should delete the invalid cookie
      assert conn.resp_cookies["ash_auth:remember_me"][:max_age] == 0
      # Should not be in session
      refute conn.private.plug_session["user_with_remember_me"]
    end

    test "when remember me cookie is not present, it does nothing", %{conn: conn} do
      conn = Helpers.sign_in_using_remember_me(conn, :ash_authentication)

      # Should not have any remember me cookies set
      assert conn.resp_cookies == %{}
      # Should not have any assigns set
      refute conn.private.plug_session["user_with_remember_me"]
    end

    test "it respects tenant and context options" do
      # Create a user with remember me strategy
      user = build_user_with_remember_me()

      # Generate a remember me token
      {:ok, remember_me_token} = generate_remember_me_token(user)

      # Set tenant and context
      conn =
        :get
        |> conn("/", %{})
        |> put_req_cookie("ash_auth:remember_me", remember_me_token)
        |> SessionPipeline.call([])
        |> Ash.PlugHelpers.set_tenant("test_tenant")
        |> Ash.PlugHelpers.set_context(%{test: "context"})
        |> Helpers.sign_in_using_remember_me(:ash_authentication,
          tenant: "test_tenant",
          context: %{test: "context"}
        )

      # Should have the user assigned
      assert conn.private.plug_session["user_with_remember_me"]
    end

    test "it handles multiple authenticated resources", %{conn: conn} do
      # This test would require multiple resources with remember me strategies
      # For now, we'll test that it doesn't crash with the existing setup
      conn = Helpers.sign_in_using_remember_me(conn, :ash_authentication)

      # Should not crash and should not have any assigns set
      refute conn.private.plug_session["user_with_remember_me"]
    end
  end
end
