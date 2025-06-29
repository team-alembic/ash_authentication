defmodule AshAuthentication.Strategy.RememberMe.Plug.HelpersTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.Strategy.RememberMe
  alias AshAuthentication.Strategy.RememberMe.Plug.Helpers
  alias Example.UserWithRememberMe
  alias Plug.Conn

  use Mimic
  import Plug.Test

  describe "sign_in_resource_with_remember_me/3" do
    test "returns conn unchanged when no remember me strategies found" do
      conn = conn(:get, "/") |> Conn.fetch_cookies()

      AshAuthentication.Info
      |> expect(:authentication_strategies, fn UserWithRememberMe -> [] end)

      result = Helpers.sign_in_resource_with_remember_me(conn, UserWithRememberMe, [])
      assert result == conn
    end

    test "returns conn unchanged when no remember me token in cookies" do
      conn = conn(:get, "/") |> Conn.fetch_cookies()

      strategy = %RememberMe{
        cookie_name: :remember_me,
        sign_in_action_name: :sign_in_with_remember_me
      }

      AshAuthentication.Info
      |> expect(:authentication_strategies, fn UserWithRememberMe -> [strategy] end)

      result = Helpers.sign_in_resource_with_remember_me(conn, UserWithRememberMe, [])
      assert result == conn
    end

    test "deletes invalid cookie and returns conn" do
      conn =
        conn(:get, "/")
        |> put_req_cookie("ash_auth:remember_me", "invalid_token")

      strategy = %RememberMe{
        cookie_name: :remember_me,
        sign_in_action_name: :sign_in_with_remember_me
      }

      AshAuthentication.Info
      |> expect(:authentication_strategies, fn UserWithRememberMe -> [strategy] end)
      |> expect(:domain!, fn UserWithRememberMe -> Example end)

      assert %{private: %{}} =
               Helpers.sign_in_resource_with_remember_me(conn, UserWithRememberMe, [])
    end
  end

  describe "put_remember_me_cookie/3" do
    test "puts cookie with correct options" do
      conn = conn(:get, "/")
      cookie_name = "ash_auth:remember_me"
      token_data = %{token: "test_token", max_age: 2_592_000}

      assert %{
               resp_cookies: %{
                 "ash_auth:remember_me" => %{
                   value: "test_token",
                   max_age: 2_592_000,
                   http_only: true,
                   secure: true,
                   same_site: "Lax"
                 }
               }
             } = Helpers.put_remember_me_cookie(conn, cookie_name, token_data)
    end
  end

  describe "delete_remember_me_cookie/2" do
    test "deletes cookie with correct options" do
      conn = conn(:get, "/")
      cookie_name = "ash_auth:remember_me"

      assert %{
               resp_cookies: %{
                 "ash_auth:remember_me" => %{
                   http_only: true,
                   max_age: 0,
                   same_site: "Lax",
                   secure: true,
                   universal_time: {{1970, 1, 1}, {0, 0, 0}}
                 }
               }
             } = Helpers.delete_remember_me_cookie(conn, cookie_name)
    end
  end

  describe "delete_all_remember_me_cookies/1" do
    test "deletes all remember me cookies" do
      conn =
        conn(:get, "/")
        |> put_req_cookie("ash_auth:remember_me", "token1")
        |> put_req_cookie("ash_auth:remember_me:custom", "token2")
        |> put_req_cookie("other_cookie", "value")

      assert %{
               resp_cookies: %{
                 "ash_auth:remember_me" => %{
                   http_only: true,
                   max_age: 0,
                   same_site: "Lax",
                   secure: true,
                   universal_time: {{1970, 1, 1}, {0, 0, 0}}
                 },
                 "ash_auth:remember_me:custom" => %{
                   http_only: true,
                   max_age: 0,
                   same_site: "Lax",
                   secure: true,
                   universal_time: {{1970, 1, 1}, {0, 0, 0}}
                 }
               }
             } = Helpers.delete_all_remember_me_cookies(conn)
    end
  end

  describe "maybe_put_remember_me_cookies/2" do
    test "returns unchanged when user has no remember_me metadata" do
      conn = conn(:get, "/")
      user = %{__metadata__: %{}}
      result_tuple = {conn, {:ok, user}}

      result = Helpers.maybe_put_remember_me_cookies(result_tuple, %{})
      assert result == result_tuple
    end

    test "returns unchanged when not a success tuple" do
      conn = conn(:get, "/")

      result = Helpers.maybe_put_remember_me_cookies(conn, %{})
      assert result == conn
    end
  end
end
