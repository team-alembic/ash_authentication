# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog.IdentityBruteForceTest do
  @moduledoc false
  use DataCase, async: false
  alias AshAuthentication.{AuditLogResource.Batcher, Info, Strategy}
  require Ash.Query

  setup do
    start_supervised!({Batcher, otp_app: :ash_authentication})
    :ok
  end

  describe "password sign-in" do
    test "allows sign-in when failures are below the threshold" do
      user = build_user_with_audit_log()
      create_failed_attempts(user.email, :password, :sign_in_with_password, 4)

      assert {:ok, _} =
               sign_in_with_password(user.email, user.__metadata__.password)
    end

    test "blocks sign-in when failures meet the threshold" do
      user = build_user_with_audit_log()
      create_failed_attempts(user.email, :password, :sign_in_with_password, 5)

      assert {:error, error} =
               sign_in_with_password(user.email, user.__metadata__.password)

      assert Exception.message(error) =~ "Authentication failed"
    end

    test "allows sign-in after the window has elapsed" do
      user = build_user_with_audit_log()

      create_failed_attempts(user.email, :password, :sign_in_with_password, 5, minutes_ago: 6)

      assert {:ok, _} =
               sign_in_with_password(user.email, user.__metadata__.password)
    end

    test "failures against different identities do not block each other" do
      user_a = build_user_with_audit_log()
      user_b = build_user_with_audit_log()

      create_failed_attempts(user_a.email, :password, :sign_in_with_password, 5)

      assert {:ok, _} =
               sign_in_with_password(user_b.email, user_b.__metadata__.password)
    end
  end

  describe "password reset request" do
    test "blocks the action when failures meet the threshold" do
      user = build_user_with_audit_log()

      create_failed_attempts(
        user.email,
        :password,
        :request_password_reset_with_password,
        5
      )

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)

      assert {:error, error} =
               Strategy.action(strategy, :reset_request, %{"email" => to_string(user.email)})

      assert Exception.message(error) =~ "Authentication failed"
    end
  end

  describe "magic link request" do
    test "blocks the action when failures meet the threshold" do
      user = build_user_with_audit_log()

      create_failed_attempts(user.email, :magic_link, :request_magic_link, 5)

      strategy = Info.strategy!(Example.UserWithAuditLog, :magic_link)

      assert {:error, error} =
               Strategy.action(strategy, :request, %{"email" => to_string(user.email)})

      assert Exception.message(error) =~ "Authentication failed"
    end
  end

  defp sign_in_with_password(email, password) do
    strategy = Info.strategy!(Example.UserWithAuditLog, :password)
    Strategy.action(strategy, :sign_in, %{"email" => to_string(email), "password" => password})
  end

  defp create_failed_attempts(identity, strategy_name, action_name, count, opts \\ []) do
    minutes_ago = Keyword.get(opts, :minutes_ago, 0)
    logged_at = DateTime.add(DateTime.utc_now(), -minutes_ago, :minute)

    for _ <- 1..count do
      Example.AuditLog
      |> Ash.Changeset.for_create(:log_activity, %{
        identity: to_string(identity),
        strategy: strategy_name,
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
