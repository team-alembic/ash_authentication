# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AuditLogResource.TransformerTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias AshAuthentication.AuditLogResource.Info

  describe "log_lifetime :infinity" do
    test "compiles without error" do
      assert {:ok, :infinity} = Info.audit_log_log_lifetime(Example.AuditLogNoExpiry)
    end

    test "has the write action" do
      {:ok, write_action_name} = Info.audit_log_write_action_name(Example.AuditLogNoExpiry)
      assert Ash.Resource.Info.action(Example.AuditLogNoExpiry, write_action_name)
    end

    test "does not have the destroy action" do
      {:ok, destroy_action_name} = Info.audit_log_destroy_action_name(Example.AuditLogNoExpiry)
      refute Ash.Resource.Info.action(Example.AuditLogNoExpiry, destroy_action_name)
    end

    test "does not have the read_expired action" do
      {:ok, read_expired_action_name} =
        Info.audit_log_read_expired_action_name(Example.AuditLogNoExpiry)

      refute Ash.Resource.Info.action(Example.AuditLogNoExpiry, read_expired_action_name)
    end
  end

  describe "default log_lifetime" do
    test "has destroy and read_expired actions" do
      {:ok, destroy_action_name} = Info.audit_log_destroy_action_name(Example.AuditLog)
      assert Ash.Resource.Info.action(Example.AuditLog, destroy_action_name)

      {:ok, read_expired_action_name} =
        Info.audit_log_read_expired_action_name(Example.AuditLog)

      assert Ash.Resource.Info.action(Example.AuditLog, read_expired_action_name)
    end
  end
end
