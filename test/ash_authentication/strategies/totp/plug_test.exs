# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.PlugTest do
  @moduledoc false
  use DataCase
  import Plug.Test

  alias AshAuthentication.{
    Errors.AuthenticationFailed,
    Info,
    Plug.Helpers,
    Strategy.Totp,
    Strategy.Totp.Plug
  }

  describe "setup/2" do
    test "it generates a TOTP secret when given a valid actor" do
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)
      user = build_user_with_totp()

      assert is_nil(user.totp_secret)

      assert {_conn, {:ok, updated_user}} =
               :post
               |> conn("/")
               |> Ash.PlugHelpers.set_actor(user)
               |> Plug.setup(strategy)
               |> Helpers.get_authentication_result()

      assert updated_user.id == user.id
      refute is_nil(updated_user.totp_secret)
      assert is_binary(updated_user.totp_secret)
    end

    test "it returns an error when no actor is set" do
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      assert {_conn, {:error, error}} =
               :post
               |> conn("/")
               |> Plug.setup(strategy)
               |> Helpers.get_authentication_result()

      assert Exception.message(error) =~ ~r/argument user is required/i
    end
  end

  describe "sign_in/2" do
    test "it signs the user in with valid identity and code" do
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)
      user = build_user_with_totp()

      {:ok, user_with_secret} = Totp.Actions.setup(strategy, %{user: user}, [])
      code = NimbleTOTP.verification_code(user_with_secret.totp_secret)

      params = %{
        "user_with_totp" => %{
          "email" => to_string(user_with_secret.email),
          "code" => code
        }
      }

      assert {_conn, {:ok, signed_in_user}} =
               :post
               |> conn("/", params)
               |> Plug.sign_in(strategy)
               |> Helpers.get_authentication_result()

      assert signed_in_user.id == user.id
    end

    test "it returns an error with invalid code" do
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)
      user = build_user_with_totp()

      {:ok, user_with_secret} = Totp.Actions.setup(strategy, %{user: user}, [])

      params = %{
        "user_with_totp" => %{
          "email" => to_string(user_with_secret.email),
          "code" => "000000"
        }
      }

      assert {_conn, {:error, %AuthenticationFailed{}}} =
               :post
               |> conn("/", params)
               |> Plug.sign_in(strategy)
               |> Helpers.get_authentication_result()
    end

    test "it returns an error when user is not found" do
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      params = %{
        "user_with_totp" => %{
          "email" => "nonexistent@example.com",
          "code" => "123456"
        }
      }

      assert {_conn, {:error, %AuthenticationFailed{}}} =
               :post
               |> conn("/", params)
               |> Plug.sign_in(strategy)
               |> Helpers.get_authentication_result()
    end

    test "it returns an error when user has no TOTP secret set up" do
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)
      user = build_user_with_totp()

      params = %{
        "user_with_totp" => %{
          "email" => to_string(user.email),
          "code" => "123456"
        }
      }

      assert {_conn, {:error, %AuthenticationFailed{}}} =
               :post
               |> conn("/", params)
               |> Plug.sign_in(strategy)
               |> Helpers.get_authentication_result()
    end
  end
end
