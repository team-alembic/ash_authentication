# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLogTest do
  @moduledoc false
  use DataCase, async: false
  alias AshAuthentication.{AuditLogResource.Batcher, Info, Strategy}
  require Ash.Query

  setup do
    start_supervised!({Batcher, otp_app: :ash_authentication})
    :ok
  end

  describe "audit log add-on" do
    test "it creates an audit log entry on successful sign in" do
      user = build_user_with_audit_log()

      params = %{
        "email" => user.email,
        "password" => user.__metadata__.password
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)

      assert {:ok, signed_in_user} = Strategy.action(strategy, :sign_in, params)
      assert signed_in_user.id == user.id

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      sign_in_log = Enum.find(logs, &(&1.action_name == :sign_in_with_password))
      assert sign_in_log.strategy == :password
      assert sign_in_log.action_name == :sign_in_with_password
      assert sign_in_log.status == :success
      assert sign_in_log.subject == "user_with_audit_log?id=#{user.id}"
      assert sign_in_log.resource == Example.UserWithAuditLog
    end

    test "it creates an audit log entry on failed sign in" do
      params = %{
        "email" => "nonexistent@example.com",
        "password" => "wrong_password"
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)

      assert {:error, _} = Strategy.action(strategy, :sign_in, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      assert [log] = logs
      assert log.strategy == :password
      assert log.action_name == :sign_in_with_password
      assert log.status == :failure
      assert is_nil(log.subject)
      assert log.resource == Example.UserWithAuditLog
    end

    test "it creates an audit log entry on registration" do
      email = "test-#{System.unique_integer([:positive])}@example.com"

      params = %{
        "email" => email,
        "password" => "password123",
        "password_confirmation" => "password123"
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)

      assert {:ok, user} = Strategy.action(strategy, :register, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      assert [log] = logs
      assert log.strategy == :password
      assert log.action_name == :register_with_password
      assert log.status == :success
      assert log.subject =~ "user_with_audit_log?id=#{user.id}"
      assert log.resource == Example.UserWithAuditLog
    end

    test "it filters sensitive arguments from audit logs" do
      email = "test-#{System.unique_integer([:positive])}@example.com"

      params = %{
        "email" => email,
        "password" => "password123",
        "password_confirmation" => "password123"
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)

      assert {:ok, _user} = Strategy.action(strategy, :register, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      assert [log] = logs
      assert is_map(log.extra_data)
      assert is_map(log.extra_data["params"])
      refute Map.has_key?(log.extra_data["params"], "password")
      refute Map.has_key?(log.extra_data["params"], "password_confirmation")
    end

    test "it filters sensitive attributes from the audit logs" do
      email = "test-#{System.unique_integer([:positive])}@example.com"

      params = %{
        "email" => email,
        "password" => "password123",
        "password_confirmation" => "password123"
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)

      assert {:ok, _user} = Strategy.action(strategy, :register, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      assert [log] = logs
      assert is_map(log.extra_data)
      assert is_map(log.extra_data["params"])
      refute Map.has_key?(log.extra_data["params"], "hashed_password")
    end

    test "sentitive attributes and arguments can be explicitly allowed" do
      email = "test-#{System.unique_integer([:positive])}@example.com"

      params = %{
        "email" => email,
        "password" => "password123",
        "password_confirmation" => "password123"
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)

      assert {:ok, _user} = Strategy.action(strategy, :register, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      assert [log] = logs
      assert is_map(log.extra_data)
      assert is_map(log.extra_data["params"])
      assert Map.has_key?(log.extra_data["params"], "email")
    end

    test "it captures logged_at timestamp" do
      user = build_user_with_audit_log()
      before_time = DateTime.utc_now()

      params = %{
        "email" => user.email,
        "password" => user.__metadata__.password
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)

      assert {:ok, _signed_in_user} = Strategy.action(strategy, :sign_in, params)

      after_time = DateTime.utc_now()

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      sign_in_log = Enum.find(logs, &(&1.action_name == :sign_in_with_password))
      assert DateTime.compare(sign_in_log.logged_at, before_time) in [:gt, :eq]
      assert DateTime.compare(sign_in_log.logged_at, after_time) in [:lt, :eq]
    end
  end

  describe "exclude_strategies configuration" do
    test "excluded strategies do not create audit logs" do
      user = build_user_with_excluded_strategies()

      params = %{
        "email" => user.email,
        "password" => user.__metadata__.password
      }

      strategy = Info.strategy!(Example.UserWithExcludedStrategies, :password)

      assert {:ok, _signed_in_user} = Strategy.action(strategy, :sign_in, params)

      Batcher.flush()

      logs =
        Example.AuditLog
        |> Ash.Query.filter(resource == Example.UserWithExcludedStrategies)
        |> Ash.read!()

      # Password strategy is NOT excluded, so sign_in should be logged
      assert Enum.any?(logs, &(&1.action_name == :sign_in_with_password))
      # Registration from the factory should also be logged
      assert Enum.any?(logs, &(&1.action_name == :register_with_password))
    end
  end

  describe "exclude_actions configuration" do
    test "excluded actions do not create audit logs" do
      user = build_user_with_excluded_actions()

      params = %{
        "email" => user.email,
        "password" => user.__metadata__.password
      }

      strategy = Info.strategy!(Example.UserWithExcludedActions, :password)

      assert {:ok, _signed_in_user} = Strategy.action(strategy, :sign_in, params)

      Batcher.flush()

      logs =
        Example.AuditLog
        |> Ash.Query.filter(resource == Example.UserWithExcludedActions)
        |> Ash.read!()

      # sign_in_with_password is excluded, so should NOT be logged
      refute Enum.any?(logs, &(&1.action_name == :sign_in_with_password))
      # Registration is NOT excluded, so should be logged
      assert Enum.any?(logs, &(&1.action_name == :register_with_password))
    end
  end

  describe "include_actions configuration (explicit includes)" do
    test "only explicitly included actions create audit logs" do
      user = build_user_with_explicit_includes()

      params = %{
        "email" => user.email,
        "password" => user.__metadata__.password
      }

      strategy = Info.strategy!(Example.UserWithExplicitIncludes, :password)

      # Sign in should be logged (it's in include_actions)
      assert {:ok, _signed_in_user} = Strategy.action(strategy, :sign_in, params)

      Batcher.flush()

      logs =
        Example.AuditLog
        |> Ash.Query.filter(resource == Example.UserWithExplicitIncludes)
        |> Ash.read!()

      # Both sign_in and register should be logged (both are explicitly included)
      assert Enum.any?(logs, &(&1.action_name == :sign_in_with_password))
      assert Enum.any?(logs, &(&1.action_name == :register_with_password))

      # If there were other actions (like reset_password), they would NOT be logged
      # since they're not in the explicit include list
    end

    test "actions not in explicit include list are not logged" do
      # This test demonstrates that only the explicitly included actions are logged
      # The resource has include_actions([:sign_in_with_password, :register_with_password])
      _user = build_user_with_explicit_includes()

      Batcher.flush()

      logs =
        Example.AuditLog
        |> Ash.Query.filter(resource == Example.UserWithExplicitIncludes)
        |> Ash.read!()

      # Only register_with_password should be logged from the user creation
      assert length(logs) == 1
      assert hd(logs).action_name == :register_with_password
    end
  end

  describe "wildcard with exclusions" do
    test "wildcard includes all actions, then applies exclusions" do
      user = build_user_with_wildcard_and_exclusions()

      params = %{
        "email" => user.email,
        "password" => user.__metadata__.password
      }

      strategy = Info.strategy!(Example.UserWithWildcardAndExclusions, :password)

      # Sign in should NOT be logged (it's excluded)
      assert {:ok, _signed_in_user} = Strategy.action(strategy, :sign_in, params)

      Batcher.flush()

      logs =
        Example.AuditLog
        |> Ash.Query.filter(resource == Example.UserWithWildcardAndExclusions)
        |> Ash.read!()

      # sign_in_with_password is excluded, so should NOT be logged
      refute Enum.any?(logs, &(&1.action_name == :sign_in_with_password))
      # register_with_password is NOT excluded, so should be logged
      assert Enum.any?(logs, &(&1.action_name == :register_with_password))
    end

    test "wildcard (:*) expands to include all actions by default" do
      # UserWithWildcardAndExclusions has include_actions([:*])
      _user = build_user_with_wildcard_and_exclusions()

      Batcher.flush()

      logs =
        Example.AuditLog
        |> Ash.Query.filter(resource == Example.UserWithWildcardAndExclusions)
        |> Ash.read!()

      # The wildcard should have included register_with_password
      assert Enum.any?(logs, &(&1.action_name == :register_with_password))
    end
  end

  describe "selective strategy includes" do
    test "only actions from included strategies are logged" do
      user = build_user_with_selective_strategy_includes()

      params = %{
        "email" => user.email,
        "password" => user.__metadata__.password
      }

      strategy = Info.strategy!(Example.UserWithSelectiveStrategyIncludes, :password)

      assert {:ok, _signed_in_user} = Strategy.action(strategy, :sign_in, params)

      Batcher.flush()

      logs =
        Example.AuditLog
        |> Ash.Query.filter(resource == Example.UserWithSelectiveStrategyIncludes)
        |> Ash.read!()

      # Password strategy is explicitly included, so its actions should be logged
      assert Enum.any?(logs, &(&1.action_name == :sign_in_with_password))
      assert Enum.any?(logs, &(&1.action_name == :register_with_password))

      # All logged actions should belong to the password strategy
      for log <- logs do
        assert log.strategy == :password
      end
    end

    test "actions from non-included strategies are not logged" do
      # This resource only includes [:password] strategy
      # If we had other strategies like OAuth, their actions wouldn't be logged
      _user = build_user_with_selective_strategy_includes()

      Batcher.flush()

      logs =
        Example.AuditLog
        |> Ash.Query.filter(resource == Example.UserWithSelectiveStrategyIncludes)
        |> Ash.read!()

      # Only password strategy actions should be present
      for log <- logs do
        assert log.strategy == :password
      end
    end
  end

  describe "empty includes configuration" do
    test "empty include lists result in no audit logs" do
      # Try to create a user - registration should NOT be logged
      # because include_actions and include_strategies are both empty
      email = "test-empty-#{System.unique_integer([:positive])}@example.com"

      params = %{
        "email" => email,
        "password" => "password123",
        "password_confirmation" => "password123"
      }

      # We need to register directly without using the factory
      # to avoid any confusion about what's being logged
      user =
        Example.UserWithEmptyIncludes
        |> Ash.Changeset.new()
        |> Ash.Changeset.for_create(:register_with_password, params)
        |> Ash.create!()

      Batcher.flush()

      logs =
        Example.AuditLog
        |> Ash.Query.filter(resource == Example.UserWithEmptyIncludes)
        |> Ash.read!()

      # No logs should be created when includes are empty
      assert Enum.empty?(logs)

      # Now try to sign in - this also shouldn't be logged
      sign_in_params = %{
        "email" => user.email,
        "password" => "password123"
      }

      strategy = Info.strategy!(Example.UserWithEmptyIncludes, :password)
      assert {:ok, _signed_in_user} = Strategy.action(strategy, :sign_in, sign_in_params)

      Batcher.flush()

      logs_after_sign_in =
        Example.AuditLog
        |> Ash.Query.filter(resource == Example.UserWithEmptyIncludes)
        |> Ash.read!()

      # Still no logs - empty includes mean nothing is logged
      assert Enum.empty?(logs_after_sign_in)
    end
  end

  describe "inclusion-first logic precedence" do
    test "exclusions only filter what was already included" do
      # This tests that the inclusion happens first, then exclusions are applied
      # If an action is not in the include list, it won't be logged even if it's
      # not in the exclude list either

      _user = build_user_with_explicit_includes()

      # The resource has:
      # include_actions([:sign_in_with_password, :register_with_password])
      # So only these two actions can possibly be logged

      Batcher.flush()

      logs =
        Example.AuditLog
        |> Ash.Query.filter(resource == Example.UserWithExplicitIncludes)
        |> Ash.read!()

      # Check that only included actions are present
      for log <- logs do
        assert log.action_name in [:sign_in_with_password, :register_with_password]
      end
    end

    test "wildcard expansion happens before exclusions" do
      # The wildcard (:*) should expand to all actions first,
      # then exclusions are applied to filter that expanded list

      _user = build_user_with_wildcard_and_exclusions()

      Batcher.flush()

      logs =
        Example.AuditLog
        |> Ash.Query.filter(resource == Example.UserWithWildcardAndExclusions)
        |> Ash.read!()

      # The wildcard expanded to all actions, but sign_in_with_password was excluded
      assert Enum.any?(logs, &(&1.action_name == :register_with_password))
      refute Enum.any?(logs, &(&1.action_name == :sign_in_with_password))
    end
  end
end
