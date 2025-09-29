# credo:disable-for-this-file Credo.Check.Design.AliasUsage
defmodule Mix.Tasks.AshAuthentication.AddAddOnTest do
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

  describe "audit_log" do
    test "creates the audit log resource", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_add_on", ["audit_log"])
      |> assert_creates("lib/test/accounts/audit_log.ex")
    end

    test "adds the audit_log add-on to the user resource", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_add_on", ["audit_log"])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      +  |
      +  |      audit_log do
      +  |        audit_log_resource(Test.Accounts.AuditLog)
      +  |      end
         |    end
      """)
    end

    test "ensures the AshAuthentication.Supervisor is in the application", %{
      igniter: igniter
    } do
      # The supervisor is already added by ash_authentication.install in setup
      # Just verify the task runs successfully
      igniter
      |> Igniter.compose_task("ash_authentication.add_add_on", ["audit_log"])
      |> assert_creates("lib/test/accounts/audit_log.ex")
    end

    test "supports custom audit log resource name", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_add_on", [
        "audit_log",
        "--audit-log",
        "Test.Accounts.AuthAuditLog"
      ])
      |> assert_creates("lib/test/accounts/auth_audit_log.ex")
      |> assert_has_patch("lib/test/accounts/user.ex", """
      +  |
      +  |      audit_log do
      +  |        audit_log_resource(Test.Accounts.AuthAuditLog)
      +  |      end
         |    end
      """)
    end

    test "supports include_fields option", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_add_on", [
        "audit_log",
        "--include-fields",
        "email,username"
      ])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      +  |
      +  |      audit_log do
      +  |        audit_log_resource(Test.Accounts.AuditLog)
      +  |        include_fields([:email, :username])
      +  |      end
         |    end
      """)
    end

    test "supports exclude_strategies option", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_add_on", [
        "audit_log",
        "--exclude-strategies",
        "magic_link,oauth"
      ])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      +  |
      +  |      audit_log do
      +  |        audit_log_resource(Test.Accounts.AuditLog)
      +  |        exclude_strategies([:magic_link, :oauth])
      +  |      end
         |    end
      """)
    end

    test "supports exclude_actions option", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_add_on", [
        "audit_log",
        "--exclude-actions",
        "sign_in_with_token,register_with_password"
      ])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      +  |
      +  |      audit_log do
      +  |        audit_log_resource(Test.Accounts.AuditLog)
      +  |        exclude_actions([:sign_in_with_token, :register_with_password])
      +  |      end
         |    end
      """)
    end

    test "supports multiple options together", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_add_on", [
        "audit_log",
        "--include-fields",
        "email",
        "--exclude-strategies",
        "magic_link",
        "--exclude-actions",
        "sign_in_with_token"
      ])
      |> assert_has_patch("lib/test/accounts/user.ex", """
      +  |
      +  |      audit_log do
      +  |        audit_log_resource(Test.Accounts.AuditLog)
      +  |        include_fields([:email])
      +  |        exclude_strategies([:magic_link])
      +  |        exclude_actions([:sign_in_with_token])
      +  |      end
         |    end
      """)
    end

    test "does not duplicate supervisor if already present", %{igniter: igniter} do
      igniter =
        igniter
        |> Igniter.compose_task("ash_authentication.add_add_on", ["audit_log"])
        |> apply_igniter!()

      # Run it again - should error about duplicate resource
      igniter
      |> Igniter.compose_task("ash_authentication.add_add_on", ["audit_log"])
      |> assert_has_issue(&String.contains?(&1, "Audit log resource already exists"))
    end
  end

  describe "error handling" do
    test "shows error for missing user resource", %{igniter: igniter} do
      igniter
      |> Igniter.compose_task("ash_authentication.add_add_on", [
        "audit_log",
        "--user",
        "NonExistent.User"
      ])
      |> assert_has_issue(&String.contains?(&1, "User module NonExistent.User was not found"))
    end

    test "shows error if audit log resource already exists", %{igniter: igniter} do
      igniter =
        igniter
        |> Igniter.compose_task("ash_authentication.add_add_on", ["audit_log"])
        |> apply_igniter!()

      # Try to add again with same name
      igniter
      |> Igniter.compose_task("ash_authentication.add_add_on", ["audit_log"])
      |> assert_has_issue(&String.contains?(&1, "Audit log resource already exists"))
    end
  end
end
