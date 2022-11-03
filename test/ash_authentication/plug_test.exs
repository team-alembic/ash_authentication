defmodule AshAuthentication.PlugTest do
  @moduledoc false
  use AshAuthentication.DataCase, async: true
  use Mimic
  alias AshAuthentication.Plug.{Defaults, Helpers}
  alias AshAuthentication.SessionPipeline
  alias Example.AuthPlug
  import Plug.Test, only: [conn: 3]

  describe "handle_success/3" do
    test "it is called when authentication is successful" do
      password = password()
      user = build_user(password: password, password_confirmation: password)

      opts = AuthPlug.init([])

      %{status: status, resp_body: resp} =
        :post
        |> conn("/user_with_username/password/callback", %{
          "user_with_username" => %{
            "username" => to_string(user.username),
            "password" => password,
            "action" => "sign_in"
          }
        })
        |> SessionPipeline.call([])
        |> AuthPlug.call(opts)

      resp = Jason.decode!(resp)

      assert status == 200
      assert resp["user"]["id"] == user.id
      assert resp["user"]["username"] == to_string(user.username)
    end
  end

  describe "handle_failure/2" do
    test "it is called when authentication is unsuccessful" do
      opts = AuthPlug.init([])

      %{status: status, resp_body: resp} =
        :post
        |> conn("/user_with_username/password/callback", %{
          "user_with_username" => %{
            "username" => username(),
            "password" => password(),
            "action" => "sign_in"
          }
        })
        |> SessionPipeline.call([])
        |> AuthPlug.call(opts)

      resp = Jason.decode!(resp)

      assert status == 401
      assert resp["status"] == "failure"
      assert resp["reason"] =~ ~r/Forbidden/
    end
  end

  describe "load_from_session/2" do
    test "it delegates to Helpers.retrieve_from_session/2" do
      conn = conn(:get, "/", %{})

      Helpers
      |> expect(:retrieve_from_session, fn rx_conn, otp_app ->
        assert otp_app == :ash_authentication
        assert conn == rx_conn
      end)

      conn
      |> AuthPlug.load_from_session([])
    end
  end

  describe "load_from_bearer/2" do
    test "it delegates to Helpers.retrieve_from_bearer/2" do
      conn = conn(:get, "/", %{})

      Helpers
      |> expect(:retrieve_from_bearer, fn rx_conn, otp_app ->
        assert otp_app == :ash_authentication
        assert conn == rx_conn
      end)

      conn
      |> AuthPlug.load_from_bearer([])
    end
  end

  describe "revoke_bearer_tokens/2" do
    test "it delegates to Helpers.revoke_bearer_tokens/2" do
      conn = conn(:get, "/", %{})

      Helpers
      |> expect(:revoke_bearer_tokens, fn rx_conn, otp_app ->
        assert otp_app == :ash_authentication
        assert conn == rx_conn
      end)

      conn
      |> AuthPlug.revoke_bearer_tokens([])
    end
  end

  describe "set_actor/2" do
    test "it delegates to Helpers.set_actor/2" do
      conn = conn(:get, "/", %{})

      Helpers
      |> expect(:set_actor, fn rx_conn, subject_name ->
        assert subject_name == :user_with_username
        assert conn == rx_conn
      end)

      conn
      |> AuthPlug.set_actor(:user_with_username)
    end
  end

  describe "store_in_session/2" do
    test "it delegates to Helpers.store_in_session/2" do
      user = build_user()

      conn = conn(:get, "/", %{})

      Helpers
      |> expect(:store_in_session, fn rx_conn, rx_user ->
        assert rx_user == user
        assert conn == rx_conn
      end)

      conn
      |> AuthPlug.store_in_session(user)
    end
  end

  describe "__using__/1" do
    defmodule WithDefaults do
      @moduledoc false
      use AshAuthentication.Plug, otp_app: :ash_authentication
    end

    test "it uses the default handle_success/3" do
      conn = conn(:get, "/", %{})
      user = build_user()
      token = Ecto.UUID.generate()

      Defaults
      |> expect(:handle_success, fn rx_conn, rx_user, rx_token ->
        assert rx_conn == conn
        assert rx_user == user
        assert rx_token == token
      end)

      conn
      |> WithDefaults.handle_success(user, token)
    end

    test "it uses the default handle_failure/2" do
      conn = conn(:get, "/", %{})
      reason = Ecto.UUID.generate()

      Defaults
      |> expect(:handle_failure, fn rx_conn, rx_reason ->
        assert rx_conn == conn
        assert rx_reason == reason
      end)

      conn
      |> WithDefaults.handle_failure(reason)
    end
  end
end
