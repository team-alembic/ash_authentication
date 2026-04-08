# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
defmodule Mix.Tasks.AshAuthentication.AddStrategy.TotpTest do
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

  describe "2fa mode (default)" do
    test "adds totp_secret attribute to the user", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.totp", [])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    attribute :totp_secret, :binary do
      + |      allow_nil?(true)
      + |      sensitive?(true)
      + |      public?(false)
      + |    end
      """)
    end

    test "adds last_totp_at attribute to the user", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.totp", [])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    attribute :last_totp_at, :datetime do
      + |      allow_nil?(true)
      + |      sensitive?(true)
      + |      public?(false)
      + |    end
      """)
    end

    test "adds the totp strategy in 2fa mode", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.totp", [])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    totp :totp do
      + |      identity_field(:email)
      + |      confirm_setup_enabled?(true)
      + |      brute_force_strategy({:audit_log, :audit_log})
      + |    end
      """)
    end

    test "does not enable sign_in in 2fa mode", %{igniter: igniter} do
      result =
        igniter
        |> Igniter.compose_task("ash_authentication.add_strategy.totp", [])

      refute diff(result) =~ "sign_in_enabled?"
    end

    test "composes the audit_log add-on", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.totp", [])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |      audit_log do
      + |        audit_log_resource(Test.Accounts.AuditLog)
      + |      end
      """)
    end

    test "creates the audit_log resource", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.totp", [])
      |> assert_creates("lib/test/accounts/audit_log.ex")
    end

    test "ensures the identity for the identity field", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.totp", [])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |  identities do
      + |    identity(:unique_email, [:email])
      + |  end
      """)
    end
  end

  describe "via parent task" do
    test "2fa mode can be invoked via ash_authentication.add_strategy", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", ["totp"])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    totp :totp do
      + |      identity_field(:email)
      + |      confirm_setup_enabled?(true)
      + |      brute_force_strategy({:audit_log, :audit_log})
      + |    end
      """)
    end

    test "primary mode can be invoked via ash_authentication.add_strategy", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy", ["totp", "--mode", "primary"])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    totp :totp do
      + |      identity_field(:email)
      + |      sign_in_enabled?(true)
      + |      confirm_setup_enabled?(true)
      + |      brute_force_strategy({:audit_log, :audit_log})
      + |    end
      """)
    end
  end

  describe "primary mode" do
    test "adds the totp strategy with sign_in_enabled", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.totp", ["--mode", "primary"])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    totp :totp do
      + |      identity_field(:email)
      + |      sign_in_enabled?(true)
      + |      confirm_setup_enabled?(true)
      + |      brute_force_strategy({:audit_log, :audit_log})
      + |    end
      """)
    end

    test "still adds both attributes", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.totp", ["--mode", "primary"])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    attribute :totp_secret, :binary do
      + |      allow_nil?(true)
      + |      sensitive?(true)
      + |      public?(false)
      + |    end
      """)
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    attribute :last_totp_at, :datetime do
      + |      allow_nil?(true)
      + |      sensitive?(true)
      + |      public?(false)
      + |    end
      """)
    end
  end

  describe "custom options" do
    test "supports custom strategy name", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.totp", ["--name", "my_totp"])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    totp :my_totp do
      + |      identity_field(:email)
      + |      confirm_setup_enabled?(true)
      + |      brute_force_strategy({:audit_log, :audit_log})
      + |    end
      """)
    end

    test "supports custom identity field", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.totp", [
        "--identity-field",
        "username"
      ])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    totp :totp do
      + |      identity_field(:username)
      + |      confirm_setup_enabled?(true)
      + |      brute_force_strategy({:audit_log, :audit_log})
      + |    end
      """)
    end
  end

  describe "error handling" do
    test "shows error for missing user resource", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.totp", [
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
      |> Igniter.compose_task("ash_authentication.add_strategy.totp", [])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    totp :totp do
      + |      identity_field(:email)
      + |      confirm_setup_enabled?(true)
      + |      brute_force_strategy({:audit_log, :audit_log})
      + |    end
      """)
    end
  end

  describe "combination with password strategy" do
    test "can add totp after password", %{igniter: igniter} do
      igniter =
        igniter
        |> Igniter.compose_task("ash_authentication.add_strategy", ["password"])
        |> apply_igniter!()

      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.totp", [])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    totp :totp do
      + |      identity_field(:email)
      + |      confirm_setup_enabled?(true)
      + |      brute_force_strategy({:audit_log, :audit_log})
      + |    end
      """)
    end
  end
end
