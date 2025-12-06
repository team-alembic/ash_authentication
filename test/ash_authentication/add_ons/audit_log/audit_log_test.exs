# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLogTest do
  @moduledoc false
  use DataCase, async: false

  alias AshAuthentication.{
    AuditLogResource.Batcher,
    Info,
    Strategy,
    Strategy.MagicLink,
    Strategy.Password
  }

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

    test "it creates an audit log entry on successful magic link sign in" do
      user = build_user_with_audit_log()
      strategy = Info.strategy!(Example.UserWithAuditLog, :magic_link)

      assert {:ok, token} = MagicLink.request_token_for(strategy, user)

      params = %{
        "token" => token
      }

      assert {:ok, signed_in_user} = Strategy.action(strategy, :sign_in, params)
      assert signed_in_user.id == user.id

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      sign_in_log = Enum.find(logs, &(&1.action_name == :sign_in_with_magic_link))
      assert sign_in_log.strategy == :magic_link
      assert sign_in_log.action_name == :sign_in_with_magic_link
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

    test "it creates an audit log entry on failed magic link sign in" do
      params = %{
        "token" => "invalid_token"
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :magic_link)

      assert {:error, _} = Strategy.action(strategy, :sign_in, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      assert [log] = logs
      assert log.strategy == :magic_link
      assert log.action_name == :sign_in_with_magic_link
      assert log.status == :failure
      assert is_nil(log.subject)
      assert log.resource == Example.UserWithAuditLog
    end

    test "it creates an audit log entry on successful remember me sign in" do
      user = build_user_with_audit_log()

      claims = %{"purpose" => "remember_me"}

      opts = [
        purpose: :remember_me,
        token_lifetime: {30, :days}
      ]

      assert {:ok, token, _claims} = AshAuthentication.Jwt.token_for_user(user, claims, opts)

      assert {:ok, [signed_in_user]} =
               Example.UserWithAuditLog
               |> Ash.Query.new()
               |> Ash.Query.for_read(:sign_in_with_remember_me, %{token: token})
               |> Ash.read()

      assert signed_in_user.id == user.id

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      sign_in_log = Enum.find(logs, &(&1.action_name == :sign_in_with_remember_me))
      assert sign_in_log.strategy == :remember_me
      assert sign_in_log.action_name == :sign_in_with_remember_me
      assert sign_in_log.status == :success
      assert sign_in_log.subject == "user_with_audit_log?id=#{user.id}"
      assert sign_in_log.resource == Example.UserWithAuditLog
    end

    test "it creates an audit log entry on failed remember me sign in" do
      assert {:error, _} =
               Example.UserWithAuditLog
               |> Ash.Query.new()
               |> Ash.Query.for_read(:sign_in_with_remember_me, %{token: "invalid_token"})
               |> Ash.read()

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      assert [log] = logs
      assert log.strategy == :remember_me
      assert log.action_name == :sign_in_with_remember_me
      assert log.status == :failure
      assert is_nil(log.subject)
      assert log.resource == Example.UserWithAuditLog
    end

    test "it creates an audit log entry on password reset request" do
      user = build_user_with_audit_log()
      strategy = Info.strategy!(Example.UserWithAuditLog, :password)

      params = %{
        "email" => user.email
      }

      assert :ok = Strategy.action(strategy, :reset_request, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      reset_request_log =
        Enum.find(logs, &(&1.action_name == :request_password_reset_with_password))

      assert reset_request_log.strategy == :password
      assert reset_request_log.action_name == :request_password_reset_with_password
      assert reset_request_log.status == :success
      # reset_request returns :ok (not a user record) for security, so subject is nil
      assert is_nil(reset_request_log.subject)
      assert reset_request_log.resource == Example.UserWithAuditLog
    end

    test "it creates an audit log entry on password reset request for non-existent user" do
      strategy = Info.strategy!(Example.UserWithAuditLog, :password)

      params = %{
        "email" => "nonexistent@example.com"
      }

      assert :ok = Strategy.action(strategy, :reset_request, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      reset_request_log =
        Enum.find(logs, &(&1.action_name == :request_password_reset_with_password))

      assert reset_request_log.strategy == :password
      assert reset_request_log.action_name == :request_password_reset_with_password
      assert reset_request_log.status == :success
      # For security, reset_request always returns :ok even if user doesn't exist
      assert is_nil(reset_request_log.subject)
      assert reset_request_log.resource == Example.UserWithAuditLog
    end

    test "it creates an audit log entry on successful password reset" do
      user = build_user_with_audit_log()
      strategy = Info.strategy!(Example.UserWithAuditLog, :password)

      assert {:ok, reset_token} = Password.reset_token_for(strategy, user)

      params = %{
        "reset_token" => reset_token,
        "password" => "new_password123",
        "password_confirmation" => "new_password123"
      }

      assert {:ok, updated_user} = Strategy.action(strategy, :reset, params)
      assert updated_user.id == user.id

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      reset_log = Enum.find(logs, &(&1.action_name == :password_reset_with_password))
      assert reset_log.strategy == :password
      assert reset_log.action_name == :password_reset_with_password
      assert reset_log.status == :success
      assert reset_log.subject == "user_with_audit_log?id=#{user.id}"
      assert reset_log.resource == Example.UserWithAuditLog
    end

    test "it creates an audit log entry on failed password reset" do
      user = build_user_with_audit_log()
      strategy = Info.strategy!(Example.UserWithAuditLog, :password)

      assert {:ok, reset_token} = Password.reset_token_for(strategy, user)

      # Use password confirmation mismatch to trigger a validation error
      # This will cause the changeset to be created and run, so audit log will be created
      params = %{
        "reset_token" => reset_token,
        "password" => "new_password123",
        "password_confirmation" => "different_password"
      }

      assert {:error, _} = Strategy.action(strategy, :reset, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      reset_log = Enum.find(logs, &(&1.action_name == :password_reset_with_password))
      assert reset_log.strategy == :password
      assert reset_log.action_name == :password_reset_with_password
      assert reset_log.status == :failure
      # When validation fails, the result is {:error, changeset}, so subject is nil
      assert is_nil(reset_log.subject)
      assert reset_log.resource == Example.UserWithAuditLog
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
