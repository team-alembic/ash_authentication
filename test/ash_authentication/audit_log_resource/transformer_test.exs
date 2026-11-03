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

  describe "a write action declared with `defaults`" do
    defmodule DefaultsDomain do
      @moduledoc false
      use Ash.Domain, validate_config_inclusion?: false

      resources do
        allow_unregistered? true
      end
    end

    test "a default create action accepting every attribute is accepted" do
      defmodule DefaultCreateAuditLog do
        @moduledoc false
        use Ash.Resource,
          data_layer: AshPostgres.DataLayer,
          domain: DefaultsDomain,
          extensions: [AshAuthentication.AuditLogResource]

        audit_log do
          log_lifetime :infinity

          write_action do
            name :create
          end
        end

        actions do
          defaults [:read, create: :*]
        end

        postgres do
          table "audit_logs_no_expiry"
          repo(Example.Repo)
        end
      end

      assert %{type: :create} = Ash.Resource.Info.action(DefaultCreateAuditLog, :create)
    end

    test "a default create action missing required attributes is rejected" do
      assert_raise Spark.Error.DslError, ~r/accept at least the required attributes/, fn ->
        defmodule NarrowDefaultCreateAuditLog do
          @moduledoc false
          use Ash.Resource,
            data_layer: AshPostgres.DataLayer,
            domain: DefaultsDomain,
            extensions: [AshAuthentication.AuditLogResource]

          audit_log do
            log_lifetime :infinity

            write_action do
              name :create
            end
          end

          actions do
            defaults [:read, create: [:id]]
          end

          postgres do
            table "audit_logs_no_expiry"
            repo(Example.Repo)
          end
        end
      end
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
