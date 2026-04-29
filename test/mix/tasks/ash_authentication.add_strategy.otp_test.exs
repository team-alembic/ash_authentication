# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
defmodule Mix.Tasks.AshAuthentication.AddStrategy.OtpTest do
  use ExUnit.Case

  import Igniter.Test

  @moduletag :igniter

  setup do
    igniter =
      test_project()
      |> Igniter.Project.Deps.add_dep({:simple_sat, ">= 0.0.0"})
      |> Igniter.compose_task("ash_authentication.install", ["--yes"])
      # These can be removed when https://github.com/hrzndhrn/rewrite/issues/39 is addressed (in igniter too)
      |> Igniter.Project.Formatter.remove_imported_dep(:ash_authentication)
      |> Igniter.Project.Formatter.remove_formatter_plugin(Spark.Formatter)
      |> apply_igniter!()

    [igniter: igniter]
  end

  describe "default invocation" do
    test "generates a migration named with add_otp_auth_strategy suffix", %{igniter: igniter} do
      # OTP composes the audit_log add-on, so the combined codegen name includes both
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.otp", [])
      |> assert_has_task("ash.codegen", ["add_audit_log_and_add_otp_auth_strategy"])
    end

    test "adds the otp strategy block", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.otp", [])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    otp :otp do
      + |      identity_field(:email)
      + |      brute_force_strategy({:audit_log, :audit_log})
      + |      sender(Test.Accounts.User.Senders.SendOtp)
      + |    end
      """)
    end

    test "adds the identity field attribute", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.otp", [])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    attribute :email, :ci_string do
      + |      allow_nil?(false)
      + |      public?(true)
      + |    end
      """)
    end

    test "ensures a unique identity for the identity field", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.otp", [])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |  identities do
      + |    identity(:unique_email, [:email])
      + |  end
      """)
    end

    test "adds a get_by lookup action", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.otp", [])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    read :get_by_email do
      + |      description("Looks up a user by their email")
      + |      get_by(:email)
      + |    end
      """)
    end

    test "adds a request_otp action", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.otp", [])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    action :request_otp do
      + |      argument :email, :ci_string do
      + |        allow_nil?(false)
      + |        description("The identity to send a one-time password to.")
      + |      end
      + |
      + |      run(AshAuthentication.Strategy.Otp.Request)
      + |      description("Send a one-time password to a user if they exist.")
      + |    end
      """)
    end

    test "adds a sign_in_with_otp action", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.otp", [])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    read :sign_in_with_otp do
      + |      description("Sign in a user with a one-time password.")
      + |      get?(true)
      + |
      + |      argument :email, :ci_string do
      + |        allow_nil?(false)
      + |      end
      + |
      + |      argument :otp, :string do
      + |        allow_nil?(false)
      + |        sensitive?(true)
      + |      end
      + |
      + |      prepare(AshAuthentication.Strategy.Otp.SignInPreparation)
      + |
      + |      metadata :token, :string do
      + |        allow_nil?(false)
      + |      end
      + |    end
      """)
    end

    test "composes the audit_log add-on", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.otp", [])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |      audit_log do
      + |        audit_log_resource(Test.Accounts.AuditLog)
      + |      end
      """)
    end

    test "creates the audit_log resource", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.otp", [])
      |> assert_creates("lib/test/accounts/audit_log.ex")
    end

    test "creates the SendOtp sender module", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.otp", [])
      |> assert_creates("lib/test/accounts/user/senders/send_otp.ex")
    end
  end

  describe "via parent task" do
    test "can be invoked via ash_authentication.add_strategy", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", ["otp"])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    otp :otp do
      + |      identity_field(:email)
      + |      brute_force_strategy({:audit_log, :audit_log})
      + |      sender(Test.Accounts.User.Senders.SendOtp)
      + |    end
      """)
    end
  end

  describe "custom options" do
    test "supports custom strategy name", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.otp", ["--name", "email_otp"])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    otp :email_otp do
      + |      identity_field(:email)
      + |      brute_force_strategy({:audit_log, :audit_log})
      + |      sender(Test.Accounts.User.Senders.SendOtp)
      + |    end
      """)
    end

    test "supports custom identity field", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.otp", [
        "--identity-field",
        "username"
      ])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    otp :otp do
      + |      identity_field(:username)
      + |      brute_force_strategy({:audit_log, :audit_log})
      + |      sender(Test.Accounts.User.Senders.SendOtp)
      + |    end
      """)
    end
  end

  describe "error handling" do
    test "shows error for missing user resource", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.otp", [
        "--user",
        "NonExistent.User"
      ])
      |> assert_has_issue(&String.contains?(&1, "User module NonExistent.User was not found"))
    end
  end

  describe "idempotency" do
    test "does not duplicate audit log add-on when already present", %{igniter: igniter} do
      igniter =
        igniter
        |> Igniter.compose_task("ash_authentication.add_add_on", ["audit_log"])
        |> apply_igniter!()

      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.otp", [])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    otp :otp do
      + |      identity_field(:email)
      + |      brute_force_strategy({:audit_log, :audit_log})
      + |      sender(Test.Accounts.User.Senders.SendOtp)
      + |    end
      """)
    end
  end

  describe "combination with password strategy" do
    test "can add otp after password", %{igniter: igniter} do
      igniter =
        igniter
        |> Igniter.compose_task("ash_authentication.add_strategy", ["password"])
        |> apply_igniter!()

      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.otp", [])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    otp :otp do
      + |      identity_field(:email)
      + |      brute_force_strategy({:audit_log, :audit_log})
      + |      sender(Test.Accounts.User.Senders.SendOtp)
      + |    end
      """)
    end
  end
end
