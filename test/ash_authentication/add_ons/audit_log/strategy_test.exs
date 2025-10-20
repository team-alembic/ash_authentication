# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog.StrategyTest do
  @moduledoc false
  use ExUnit.Case, async: true
  alias AshAuthentication.{AddOn.AuditLog, Info, Strategy}

  describe "Strategy protocol implementation" do
    setup do
      strategy = Info.strategy!(Example.UserWithAuditLog, :audit_log)
      {:ok, strategy: strategy}
    end

    test "name/1 returns the strategy name", %{strategy: strategy} do
      assert Strategy.name(strategy) == :audit_log
    end

    test "phases/1 returns empty list", %{strategy: strategy} do
      assert Strategy.phases(strategy) == []
    end

    test "actions/1 returns empty list", %{strategy: strategy} do
      assert Strategy.actions(strategy) == []
    end

    test "method_for_phase/2 returns :get", %{strategy: strategy} do
      assert Strategy.method_for_phase(strategy, :any_phase) == :get
    end

    test "routes/1 returns empty list", %{strategy: strategy} do
      assert Strategy.routes(strategy) == []
    end

    test "plug/3 returns connection unchanged", %{strategy: strategy} do
      conn = %Plug.Conn{}
      assert Strategy.plug(strategy, :any_phase, conn) == conn
    end

    test "action/4 returns authentication failed error", %{strategy: strategy} do
      assert {:error, error} = Strategy.action(strategy, :any_action, %{}, [])
      assert error.__struct__ == AshAuthentication.Errors.AuthenticationFailed
      assert error.caused_by.message =~ "Spurious attempt to call an action on audit-log strategy"
    end

    test "tokens_required?/1 returns false", %{strategy: strategy} do
      refute Strategy.tokens_required?(strategy)
    end
  end

  describe "audit log strategy struct" do
    test "has correct fields" do
      strategy = %AuditLog{
        audit_log_resource: Example.AuditLog,
        exclude_strategies: [:password],
        exclude_actions: [:sign_in],
        name: :my_audit_log,
        provider: :audit_log,
        include_fields: [:email],
        resource: Example.User
      }

      assert strategy.audit_log_resource == Example.AuditLog
      assert strategy.exclude_strategies == [:password]
      assert strategy.exclude_actions == [:sign_in]
      assert strategy.name == :my_audit_log
      assert strategy.provider == :audit_log
      assert strategy.include_fields == [:email]
      assert strategy.resource == Example.User
    end

    test "has correct default values" do
      strategy = %AuditLog{}

      assert strategy.audit_log_resource == nil
      assert strategy.exclude_strategies == []
      assert strategy.exclude_actions == []
      assert strategy.name == :audit_log
      assert strategy.provider == :audit_log
      assert strategy.include_fields == []
      assert strategy.resource == nil
    end
  end
end
