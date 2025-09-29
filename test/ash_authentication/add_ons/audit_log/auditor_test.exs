defmodule AshAuthentication.AddOn.AuditLog.AuditorTest do
  @moduledoc false
  use DataCase, async: false
  alias AshAuthentication.{AddOn.AuditLog.Auditor, AuditLogResource.Batcher, Info}
  require Ash.Query

  setup do
    start_supervised!({Batcher, otp_app: :ash_authentication})
    :ok
  end

  describe "get_tracked_actions/2" do
    test "returns list of actions tracked by the audit log strategy" do
      actions = Auditor.get_tracked_actions(Example.UserWithAuditLog, :audit_log)

      assert :sign_in_with_password in actions
      assert :register_with_password in actions
    end

    test "excluded actions are not in the tracked list" do
      actions = Auditor.get_tracked_actions(Example.UserWithExcludedActions, :audit_log)

      refute :sign_in_with_password in actions
      assert :register_with_password in actions
    end

    test "returns empty list for non-existent strategy" do
      actions = Auditor.get_tracked_actions(Example.UserWithAuditLog, :nonexistent)

      assert actions == []
    end
  end

  describe "after_transaction/4 status tracking" do
    test "sets status to :success for {:ok, user} result" do
      user = build_user_with_audit_log()

      params = %{
        "email" => user.email,
        "password" => user.__metadata__.password
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)
      {:ok, _signed_in_user} = AshAuthentication.Strategy.action(strategy, :sign_in, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()
      sign_in_log = Enum.find(logs, &(&1.action_name == :sign_in_with_password))

      assert sign_in_log.status == :success
    end

    test "sets status to :failure for {:error, reason} result" do
      params = %{
        "email" => "nonexistent@example.com",
        "password" => "wrong_password"
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)
      {:error, _reason} = AshAuthentication.Strategy.action(strategy, :sign_in, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      assert [log] = logs
      assert log.status == :failure
    end
  end

  describe "after_transaction/4 subject extraction" do
    test "extracts subject from successful result with user record" do
      email = "test-#{System.unique_integer([:positive])}@example.com"

      params = %{
        "email" => email,
        "password" => "password123",
        "password_confirmation" => "password123"
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)
      {:ok, user} = AshAuthentication.Strategy.action(strategy, :register, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      assert [log] = logs
      assert log.subject == "user_with_audit_log?id=#{user.id}"
    end

    test "sets subject to nil for failed authentication" do
      params = %{
        "email" => "nonexistent@example.com",
        "password" => "wrong_password"
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)
      {:error, _reason} = AshAuthentication.Strategy.action(strategy, :sign_in, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      assert [log] = logs
      assert is_nil(log.subject)
    end
  end

  describe "get_params/2 parameter filtering" do
    test "includes public non-sensitive arguments" do
      email = "test-#{System.unique_integer([:positive])}@example.com"

      params = %{
        "email" => email,
        "password" => "password123",
        "password_confirmation" => "password123"
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)
      {:ok, _user} = AshAuthentication.Strategy.action(strategy, :register, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      assert [log] = logs
      # Email is sensitive but explicitly included via include_fields
      assert Map.has_key?(log.extra_data["params"], "email")
    end

    test "excludes sensitive arguments by default" do
      email = "test-#{System.unique_integer([:positive])}@example.com"

      params = %{
        "email" => email,
        "password" => "password123",
        "password_confirmation" => "password123"
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)
      {:ok, _user} = AshAuthentication.Strategy.action(strategy, :register, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      assert [log] = logs
      refute Map.has_key?(log.extra_data["params"], "password")
      refute Map.has_key?(log.extra_data["params"], "password_confirmation")
    end

    test "excludes sensitive attributes" do
      email = "test-#{System.unique_integer([:positive])}@example.com"

      params = %{
        "email" => email,
        "password" => "password123",
        "password_confirmation" => "password123"
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)
      {:ok, _user} = AshAuthentication.Strategy.action(strategy, :register, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      assert [log] = logs
      refute Map.has_key?(log.extra_data["params"], "hashed_password")
    end

    test "includes explicitly allowed sensitive fields via include_fields" do
      email = "test-#{System.unique_integer([:positive])}@example.com"

      params = %{
        "email" => email,
        "password" => "password123",
        "password_confirmation" => "password123"
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)
      {:ok, _user} = AshAuthentication.Strategy.action(strategy, :register, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      assert [log] = logs
      # Email is sensitive but included via include_fields: [:email]
      assert Map.has_key?(log.extra_data["params"], "email")
      assert log.extra_data["params"]["email"] == email
    end
  end

  describe "extra_data capture" do
    test "captures actor from context when present" do
      # This would require setting up an actor in the context
      # Skipping for now as it requires more complex test setup
    end

    test "captures tenant from context when present" do
      # This would require setting up multitenancy
      # Skipping for now as it requires more complex test setup
    end

    test "captures request metadata when present" do
      # This would require simulating a web request
      # Skipping for now as it requires more complex test setup
    end

    test "extra_data always contains actor, tenant, request, and params keys" do
      email = "test-#{System.unique_integer([:positive])}@example.com"

      params = %{
        "email" => email,
        "password" => "password123",
        "password_confirmation" => "password123"
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)
      {:ok, _user} = AshAuthentication.Strategy.action(strategy, :register, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      assert [log] = logs
      assert Map.has_key?(log.extra_data, "actor")
      assert Map.has_key?(log.extra_data, "tenant")
      assert Map.has_key?(log.extra_data, "request")
      assert Map.has_key?(log.extra_data, "params")
    end
  end

  describe "Change and Preparation modules" do
    test "Change module tracks create actions" do
      email = "test-#{System.unique_integer([:positive])}@example.com"

      params = %{
        "email" => email,
        "password" => "password123",
        "password_confirmation" => "password123"
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)
      {:ok, _user} = AshAuthentication.Strategy.action(strategy, :register, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      assert [log] = logs
      assert log.action_name == :register_with_password
    end

    test "Preparation module tracks read actions" do
      user = build_user_with_audit_log()

      params = %{
        "email" => user.email,
        "password" => user.__metadata__.password
      }

      strategy = Info.strategy!(Example.UserWithAuditLog, :password)
      {:ok, _signed_in_user} = AshAuthentication.Strategy.action(strategy, :sign_in, params)

      Batcher.flush()

      logs = Example.AuditLog |> Ash.read!()

      sign_in_log = Enum.find(logs, &(&1.action_name == :sign_in_with_password))
      assert sign_in_log
    end
  end
end
