# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.ActionsTest do
  @moduledoc false
  use DataCase

  alias AshAuthentication.{
    Errors.AuthenticationFailed,
    Info,
    Strategy.Totp.Actions
  }

  describe "setup/3" do
    test "it generates a TOTP secret for the user" do
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      assert is_nil(user.totp_secret)

      assert {:ok, updated_user} = Actions.setup(strategy, %{user: user}, [])

      assert updated_user.id == user.id
      refute is_nil(updated_user.totp_secret)
      assert is_binary(updated_user.totp_secret)
    end

    test "it overwrites existing secret when setup is called again" do
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      {:ok, user_with_secret} = Actions.setup(strategy, %{user: user}, [])
      first_secret = user_with_secret.totp_secret

      {:ok, user_with_new_secret} = Actions.setup(strategy, %{user: user_with_secret}, [])
      second_secret = user_with_new_secret.totp_secret

      refute first_secret == second_secret
    end
  end

  describe "sign_in/3" do
    test "it signs in the user with valid identity and code" do
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      {:ok, user_with_secret} = Actions.setup(strategy, %{user: user}, [])
      code = NimbleTOTP.verification_code(user_with_secret.totp_secret)

      assert {:ok, signed_in_user} =
               Actions.sign_in(
                 strategy,
                 %{strategy.identity_field => user_with_secret.email, "code" => code},
                 []
               )

      assert signed_in_user.id == user.id
    end

    test "it returns an error with invalid code" do
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      {:ok, user_with_secret} = Actions.setup(strategy, %{user: user}, [])

      assert {:error, %AuthenticationFailed{}} =
               Actions.sign_in(
                 strategy,
                 %{strategy.identity_field => user_with_secret.email, "code" => "000000"},
                 []
               )
    end

    test "it returns an error when user is not found" do
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      assert {:error, %AuthenticationFailed{}} =
               Actions.sign_in(
                 strategy,
                 %{strategy.identity_field => "nonexistent@example.com", "code" => "123456"},
                 []
               )
    end
  end

  describe "verify/3" do
    test "it returns true for a valid code" do
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      {:ok, user_with_secret} = Actions.setup(strategy, %{user: user}, [])
      code = NimbleTOTP.verification_code(user_with_secret.totp_secret)

      assert {:ok, true} = Actions.verify(strategy, %{user: user_with_secret, code: code}, [])
    end

    test "it returns false for an invalid code" do
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      {:ok, user_with_secret} = Actions.setup(strategy, %{user: user}, [])

      assert {:ok, false} =
               Actions.verify(strategy, %{user: user_with_secret, code: "000000"}, [])
    end

    test "it returns false for wrong format code" do
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      {:ok, user_with_secret} = Actions.setup(strategy, %{user: user}, [])

      assert {:ok, false} =
               Actions.verify(strategy, %{user: user_with_secret, code: "invalid"}, [])
    end
  end
end
