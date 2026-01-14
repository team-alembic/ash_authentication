# SPDX-FileCopyrightText: 2025 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.AuditLogBruteForceTest do
  @moduledoc false
  use DataCase, async: false
  alias AshAuthentication.{AuditLogResource.Batcher, Info, Strategy}
  require Ash.Query

  setup do
    start_supervised!({Batcher, otp_app: :ash_authentication})
    :ok
  end

  describe "TOTP audit log brute force protection" do
    test "allows request when below failure threshold" do
      user = build_user_with_audit_log()
      {:ok, strategy} = Info.strategy(Example.UserWithAuditLog, :totp)

      # Setup TOTP for the user
      {:ok, user_with_secret} = Strategy.action(strategy, :setup, %{user: user}, [])

      # Create 4 failed attempts (below the default threshold of 5)
      create_failed_totp_attempts(user_with_secret, 4)

      # Generate a valid code
      code = NimbleTOTP.verification_code(user_with_secret.totp_secret)

      # 5th attempt should succeed since we're at 4 failures
      {:ok, signed_in_user} =
        Strategy.action(
          strategy,
          :sign_in,
          %{strategy.identity_field => user_with_secret.email, "code" => code},
          []
        )

      assert signed_in_user.id == user.id
    end

    test "blocks request when at failure threshold" do
      user = build_user_with_audit_log()
      {:ok, strategy} = Info.strategy(Example.UserWithAuditLog, :totp)

      # Setup TOTP for the user
      {:ok, user_with_secret} = Strategy.action(strategy, :setup, %{user: user}, [])

      # Create 5 failed attempts (at the default threshold)
      create_failed_totp_attempts(user_with_secret, 5)

      # Generate a valid code
      code = NimbleTOTP.verification_code(user_with_secret.totp_secret)

      # 6th attempt should be blocked
      assert {:error, error} =
               Strategy.action(
                 strategy,
                 :sign_in,
                 %{strategy.identity_field => user_with_secret.email, "code" => code},
                 []
               )

      assert Exception.message(error) =~ "Authentication failed"
    end

    test "allows request after window expires" do
      user = build_user_with_audit_log()
      {:ok, strategy} = Info.strategy(Example.UserWithAuditLog, :totp)

      # Setup TOTP for the user
      {:ok, user_with_secret} = Strategy.action(strategy, :setup, %{user: user}, [])

      # Create 5 failed attempts older than the window (6 minutes ago)
      create_failed_totp_attempts(user_with_secret, 5, minutes_ago: 6)

      # Generate a valid code
      code = NimbleTOTP.verification_code(user_with_secret.totp_secret)

      # Attempt should succeed since old failures are outside the window
      {:ok, signed_in_user} =
        Strategy.action(
          strategy,
          :sign_in,
          %{strategy.identity_field => user_with_secret.email, "code" => code},
          []
        )

      assert signed_in_user.id == user.id
    end

    test "failures from different users don't affect each other" do
      user_a = build_user_with_audit_log()
      user_b = build_user_with_audit_log()
      {:ok, strategy} = Info.strategy(Example.UserWithAuditLog, :totp)

      # Setup TOTP for both users
      {:ok, user_a_with_secret} = Strategy.action(strategy, :setup, %{user: user_a}, [])
      {:ok, user_b_with_secret} = Strategy.action(strategy, :setup, %{user: user_b}, [])

      # Create 5 failed attempts for user A (at threshold)
      create_failed_totp_attempts(user_a_with_secret, 5)

      # User B should still be able to sign in
      code_b = NimbleTOTP.verification_code(user_b_with_secret.totp_secret)

      {:ok, signed_in_user_b} =
        Strategy.action(
          strategy,
          :sign_in,
          %{strategy.identity_field => user_b_with_secret.email, "code" => code_b},
          []
        )

      assert signed_in_user_b.id == user_b.id

      # But user A should be blocked
      code_a = NimbleTOTP.verification_code(user_a_with_secret.totp_secret)

      assert {:error, _} =
               Strategy.action(
                 strategy,
                 :sign_in,
                 %{strategy.identity_field => user_a_with_secret.email, "code" => code_a},
                 []
               )
    end

    test "failures are counted across all TOTP actions" do
      user = build_user_with_audit_log()
      {:ok, strategy} = Info.strategy(Example.UserWithAuditLog, :totp)

      # Setup TOTP for the user
      {:ok, user_with_secret} = Strategy.action(strategy, :setup, %{user: user}, [])

      # Create 3 failures from verify action and 2 from sign_in action
      create_failed_totp_attempts(user_with_secret, 3, action_name: :verify_with_totp)
      create_failed_totp_attempts(user_with_secret, 2, action_name: :sign_in_with_totp)

      # Total is 5 failures, so next attempt should be blocked
      code = NimbleTOTP.verification_code(user_with_secret.totp_secret)

      assert {:error, _} =
               Strategy.action(
                 strategy,
                 :sign_in,
                 %{strategy.identity_field => user_with_secret.email, "code" => code},
                 []
               )
    end

    test "verify action is also protected by brute force" do
      user = build_user_with_audit_log()
      {:ok, strategy} = Info.strategy(Example.UserWithAuditLog, :totp)

      # Setup TOTP for the user
      {:ok, user_with_secret} = Strategy.action(strategy, :setup, %{user: user}, [])

      # Create 5 failed attempts
      create_failed_totp_attempts(user_with_secret, 5)

      # Generate a valid code
      code = NimbleTOTP.verification_code(user_with_secret.totp_secret)

      # Verify action should also be blocked
      assert {:error, error} =
               Strategy.action(strategy, :verify, %{user: user_with_secret, code: code}, [])

      assert Exception.message(error) =~ "Authentication failed"
    end
  end

  defp create_failed_totp_attempts(user, count, opts \\ []) do
    action_name = Keyword.get(opts, :action_name, :sign_in_with_totp)
    minutes_ago = Keyword.get(opts, :minutes_ago, 0)

    subject = AshAuthentication.user_to_subject(user)
    logged_at = DateTime.add(DateTime.utc_now(), -minutes_ago, :minute)

    for _ <- 1..count do
      Example.AuditLog
      |> Ash.Changeset.for_create(:log_activity, %{
        subject: subject,
        strategy: :totp,
        audit_log: :audit_log,
        logged_at: logged_at,
        action_name: action_name,
        status: :failure,
        extra_data: %{},
        resource: Example.UserWithAuditLog
      })
      |> Ash.create!(authorize?: false)
    end
  end
end
