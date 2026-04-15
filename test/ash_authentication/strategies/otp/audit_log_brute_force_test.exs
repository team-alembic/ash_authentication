# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Otp.AuditLogBruteForceTest do
  @moduledoc false
  use DataCase, async: false

  import ExUnit.CaptureLog

  alias AshAuthentication.{AuditLogResource.Batcher, Info, Strategy}

  setup do
    start_supervised!({Batcher, otp_app: :ash_authentication})
    :ok
  end

  describe "OTP audit log brute force protection" do
    test "allows sign-in when below failure threshold" do
      user = build_user_with_audit_log()
      {:ok, strategy} = Info.strategy(Example.UserWithAuditLog, :otp)

      create_failed_otp_attempts(user, 4)

      otp_code = request_and_extract_code(strategy, to_string(user.email))

      assert {:ok, signed_in_user} =
               Strategy.action(strategy, :sign_in, %{
                 "email" => to_string(user.email),
                 "otp" => otp_code
               })

      assert signed_in_user.id == user.id
    end

    test "blocks sign-in when at failure threshold" do
      user = build_user_with_audit_log()
      {:ok, strategy} = Info.strategy(Example.UserWithAuditLog, :otp)

      otp_code = request_and_extract_code(strategy, to_string(user.email))

      create_failed_otp_attempts(user, 5)

      assert {:error, error} =
               Strategy.action(strategy, :sign_in, %{
                 "email" => to_string(user.email),
                 "otp" => otp_code
               })

      assert Exception.message(error) =~ "Authentication failed"
    end

    test "allows sign-in after window expires" do
      user = build_user_with_audit_log()
      {:ok, strategy} = Info.strategy(Example.UserWithAuditLog, :otp)

      create_failed_otp_attempts(user, 5, minutes_ago: 6)

      otp_code = request_and_extract_code(strategy, to_string(user.email))

      assert {:ok, signed_in_user} =
               Strategy.action(strategy, :sign_in, %{
                 "email" => to_string(user.email),
                 "otp" => otp_code
               })

      assert signed_in_user.id == user.id
    end

    test "failures from different users don't affect each other" do
      user_a = build_user_with_audit_log()
      user_b = build_user_with_audit_log()
      {:ok, strategy} = Info.strategy(Example.UserWithAuditLog, :otp)

      # Generate an OTP for user_a before seeding failures so there's a
      # token to sign in against once user_a is blocked.
      otp_code_a = request_and_extract_code(strategy, to_string(user_a.email))

      create_failed_otp_attempts(user_a, 5)

      # User B is unaffected and can still request + sign in normally.
      otp_code_b = request_and_extract_code(strategy, to_string(user_b.email))

      assert {:ok, signed_in_user_b} =
               Strategy.action(strategy, :sign_in, %{
                 "email" => to_string(user_b.email),
                 "otp" => otp_code_b
               })

      assert signed_in_user_b.id == user_b.id

      # User A is blocked even with a valid OTP code.
      assert {:error, _} =
               Strategy.action(strategy, :sign_in, %{
                 "email" => to_string(user_a.email),
                 "otp" => otp_code_a
               })
    end

    test "failures are counted across request_otp and sign_in_with_otp" do
      user = build_user_with_audit_log()
      {:ok, strategy} = Info.strategy(Example.UserWithAuditLog, :otp)

      otp_code = request_and_extract_code(strategy, to_string(user.email))

      create_failed_otp_attempts(user, 3, action_name: :request_otp)
      create_failed_otp_attempts(user, 2, action_name: :sign_in_with_otp)

      assert {:error, error} =
               Strategy.action(strategy, :sign_in, %{
                 "email" => to_string(user.email),
                 "otp" => otp_code
               })

      assert Exception.message(error) =~ "Authentication failed"
    end

    test "request_otp action is also protected by brute force" do
      user = build_user_with_audit_log()
      {:ok, strategy} = Info.strategy(Example.UserWithAuditLog, :otp)

      create_failed_otp_attempts(user, 5)

      assert {:error, error} =
               Strategy.action(strategy, :request, %{"email" => to_string(user.email)})

      assert Exception.message(error) =~ "Authentication failed"
    end
  end

  defp request_and_extract_code(strategy, email) do
    log =
      capture_log(fn ->
        :ok = Strategy.action(strategy, :request, %{"email" => email})
      end)

    log
    |> String.split("code \"", parts: 2)
    |> Enum.at(1)
    |> String.split("\"", parts: 2)
    |> Enum.at(0)
  end

  defp create_failed_otp_attempts(user, count, opts \\ []) do
    action_name = Keyword.get(opts, :action_name, :sign_in_with_otp)
    minutes_ago = Keyword.get(opts, :minutes_ago, 0)

    subject = AshAuthentication.user_to_subject(user)
    logged_at = DateTime.add(DateTime.utc_now(), -minutes_ago, :minute)

    for _ <- 1..count do
      Example.AuditLog
      |> Ash.Changeset.for_create(:log_activity, %{
        subject: subject,
        strategy: :otp,
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
