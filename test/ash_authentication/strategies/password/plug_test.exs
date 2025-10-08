# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Password.PlugTest do
  @moduledoc false
  use DataCase
  import ExUnit.CaptureLog
  import Plug.Test

  alias AshAuthentication.{
    Errors.AuthenticationFailed,
    Errors.UnconfirmedUser,
    Info,
    Plug.Helpers,
    Strategy.Password,
    Strategy.Password.Plug
  }

  describe "register/2" do
    test "when given valid parameters, it registers a new user" do
      {:ok, strategy} = Info.strategy(Example.User, :password)
      username = username()
      password = password()

      params = %{
        "user" => %{
          "username" => username,
          "password" => password,
          "password_confirmation" => password
        }
      }

      assert {_conn, {:ok, user}} =
               :post
               |> conn("/", params)
               |> Plug.register(strategy)
               |> Helpers.get_authentication_result()

      assert to_string(user.username) == username
      assert strategy.hash_provider.valid?(password, user.hashed_password)
    end

    test "when given invalid parameters, it returns an error" do
      {:ok, strategy} = Info.strategy(Example.User, :password)

      params = %{
        "user" => %{
          "username" => username()
        }
      }

      assert {_conn, {:error, error}} =
               :post
               |> conn("/", params)
               |> Plug.register(strategy)
               |> Helpers.get_authentication_result()

      assert Exception.message(error) =~ ~r/argument password_confirmation is required/
    end
  end

  describe "sign_in/2" do
    test "it signs the user in when given valid credentials" do
      {:ok, strategy} = Info.strategy(Example.User, :password)
      password = password()
      user = build_user(password: password, password_confirmation: password)

      params = %{
        "user" => %{
          "username" => user.username,
          "password" => password
        }
      }

      assert {_conn, {:ok, signed_in_user}} =
               :post
               |> conn("/", params)
               |> Plug.sign_in(strategy)
               |> Helpers.get_authentication_result()

      assert signed_in_user.id == user.id
    end

    test "it returns an error when the user is not present" do
      {:ok, strategy} = Info.strategy(Example.User, :password)

      params = %{
        "user" => %{
          "username" => username(),
          "password" => password()
        }
      }

      assert {_conn, {:error, error}} =
               :post
               |> conn("/", params)
               |> Plug.sign_in(strategy)
               |> Helpers.get_authentication_result()

      assert Exception.message(error) =~ ~r/authentication failed/i
    end

    test "it returns an error when the password is incorrect" do
      {:ok, strategy} = Info.strategy(Example.User, :password)
      password = password()
      user = build_user(password: password, password_confirmation: password)

      params = %{
        "user" => %{
          "username" => user.username,
          "password" => password()
        }
      }

      assert {_conn, {:error, error}} =
               :post
               |> conn("/", params)
               |> Plug.sign_in(strategy)
               |> Helpers.get_authentication_result()

      assert Exception.message(error) =~ ~r/authentication failed/i
    end

    test "it returns an error when account confirmation is required and instead it is not" do
      {:ok, strategy} = Info.strategy(Example.User, :password)
      strategy = %{strategy | require_confirmed_with: :confirmed_at}

      password = password()
      user = build_user(password: password, password_confirmation: password)

      params = %{
        "user" => %{
          "username" => user.username,
          "password" => password
        }
      }

      assert {_conn,
              {
                :error,
                %AuthenticationFailed{
                  caused_by: %UnconfirmedUser{} = error
                }
              }} =
               :post
               |> conn("/", params)
               |> Plug.sign_in(strategy)
               |> Helpers.get_authentication_result()

      assert Exception.message(error) =~ ~r/must be confirmed/i
    end

    test "it does NOT return an error if the user is unconfirmed but the confirmation is not required" do
      {:ok, strategy} = Info.strategy(Example.User, :password)
      strategy = %{strategy | require_confirmed_with: nil}
      password = password()
      user = build_user(password: password, password_confirmation: password)

      params = %{
        "user" => %{
          "username" => user.username,
          "password" => password
        }
      }

      assert {_conn, {:ok, signed_in_user}} =
               :post
               |> conn("/", params)
               |> Plug.sign_in(strategy)
               |> Helpers.get_authentication_result()

      assert signed_in_user.id == user.id
    end

    test "it does NOT return an error if the user is confirmed, and the confirmation is required" do
      {:ok, strategy} = Info.strategy(Example.User, :password)
      strategy = %{strategy | require_confirmed_with: :confirmed_at}
      password = password()

      # Need to build a confirmed user
      user =
        build_user(
          password: password,
          password_confirmation: password
        )

      user =
        Ash.Seed.update!(user, %{confirmed_at: DateTime.utc_now()})

      params = %{
        "user" => %{
          "username" => user.username,
          "password" => password
        }
      }

      assert {_conn, {:ok, signed_in_user}} =
               :post
               |> conn("/", params)
               |> Plug.sign_in(strategy)
               |> Helpers.get_authentication_result()

      assert signed_in_user.id == user.id
    end
  end

  describe "reset_request/2" do
    test "it sends a reset token when the user exists" do
      {:ok, strategy} = Info.strategy(Example.User, :password)
      user = build_user()

      params = %{
        "user" => %{
          "username" => user.username
        }
      }

      log =
        capture_log(fn ->
          assert {_conn, {:ok, nil}} =
                   :post
                   |> conn("/", params)
                   |> Plug.reset_request(strategy)
                   |> Helpers.get_authentication_result()
        end)

      assert log =~ ~r/password reset request for user #{user.username}/i
    end

    test "it doesn't send a reset token if the user doesn't exist" do
      {:ok, strategy} = Info.strategy(Example.User, :password)

      params = %{
        "user" => %{
          "username" => username()
        }
      }

      log =
        capture_log(fn ->
          assert {_conn, {:ok, nil}} =
                   :post
                   |> conn("/", params)
                   |> Plug.reset_request(strategy)
                   |> Helpers.get_authentication_result()
        end)

      refute log =~ ~r/password reset request/i
    end
  end

  describe "reset/2" do
    test "it resets the user's password when presented with a correct reset token" do
      {:ok, strategy} = Info.strategy(Example.User, :password)
      user = build_user()
      assert {:ok, token} = Password.reset_token_for(strategy, user)

      new_password = password()

      params = %{
        "user" => %{
          "reset_token" => token,
          "password" => new_password,
          "password_confirmation" => new_password
        }
      }

      assert {_conn, {:ok, updated_user}} =
               :post
               |> conn("/", params)
               |> Plug.reset(strategy)
               |> Helpers.get_authentication_result()

      assert user.id == updated_user.id
      assert user.hashed_password != updated_user.hashed_password
      assert strategy.hash_provider.valid?(new_password, updated_user.hashed_password)
    end
  end
end
