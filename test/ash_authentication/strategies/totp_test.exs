# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.TotpTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.{Info, Strategy}

  describe "TOTP integration" do
    test "full flow: create user, setup TOTP, sign in with code" do
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      # User starts without a TOTP secret
      assert is_nil(user.totp_secret)

      # Setup TOTP for the user
      {:ok, user_with_secret} = Strategy.action(strategy, :setup, %{user: user}, [])

      # Secret is now set
      refute is_nil(user_with_secret.totp_secret)
      assert is_binary(user_with_secret.totp_secret)

      # Generate a valid code
      code = NimbleTOTP.verification_code(user_with_secret.totp_secret)

      # Sign in with the code
      {:ok, signed_in_user} =
        Strategy.action(
          strategy,
          :sign_in,
          %{strategy.identity_field => user_with_secret.email, "code" => code},
          []
        )

      # Verify the sign-in succeeded
      assert signed_in_user.id == user.id
      assert signed_in_user.__metadata__.token
    end

    test "sign_in updates last_totp_at field" do
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      # Setup TOTP
      {:ok, user_with_secret} = Strategy.action(strategy, :setup, %{user: user}, [])

      # last_totp_at should be nil before first sign-in
      assert is_nil(user_with_secret.last_totp_at)

      # Generate and use a code
      code = NimbleTOTP.verification_code(user_with_secret.totp_secret)

      {:ok, signed_in_user} =
        Strategy.action(
          strategy,
          :sign_in,
          %{strategy.identity_field => user_with_secret.email, "code" => code},
          []
        )

      # Reload to verify database persistence (sign_in_preparation updates via a separate changeset)
      {:ok, reloaded_user} = Ash.get(Example.UserWithTotp, signed_in_user.id, authorize?: false)

      # last_totp_at should be updated
      refute is_nil(reloaded_user.last_totp_at)

      # The timestamp should be recent (within the last minute)
      assert DateTime.diff(DateTime.utc_now(), reloaded_user.last_totp_at, :second) < 60
    end

    test "same code cannot be reused within the same period" do
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      # Setup TOTP
      {:ok, user_with_secret} = Strategy.action(strategy, :setup, %{user: user}, [])

      # Generate a code
      code = NimbleTOTP.verification_code(user_with_secret.totp_secret)

      # First sign-in should succeed
      {:ok, _signed_in_user} =
        Strategy.action(
          strategy,
          :sign_in,
          %{strategy.identity_field => user_with_secret.email, "code" => code},
          []
        )

      # Same code should be rejected on second attempt
      assert {:error, _error} =
               Strategy.action(
                 strategy,
                 :sign_in,
                 %{strategy.identity_field => user_with_secret.email, "code" => code},
                 []
               )
    end

    test "verify action returns true for valid code" do
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      # Setup TOTP
      {:ok, user_with_secret} = Strategy.action(strategy, :setup, %{user: user}, [])

      # Generate a valid code
      code = NimbleTOTP.verification_code(user_with_secret.totp_secret)

      # Verify the code
      {:ok, result} =
        Strategy.action(strategy, :verify, %{user: user_with_secret, code: code}, [])

      assert result == true
    end

    test "verify action returns false for invalid code" do
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      # Setup TOTP
      {:ok, user_with_secret} = Strategy.action(strategy, :setup, %{user: user}, [])

      # Verify with invalid code
      {:ok, result} =
        Strategy.action(strategy, :verify, %{user: user_with_secret, code: "000000"}, [])

      assert result == false
    end
  end
end
