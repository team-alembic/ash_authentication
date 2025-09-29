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
      assert is_nil(sign_in_log.subject)
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
end
