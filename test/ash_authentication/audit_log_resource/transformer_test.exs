# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AuditLogResource.TransformerTest do
  @moduledoc false
  use ExUnit.Case, async: true
  alias Ash.Resource.Info

  defmodule Domain do
    @moduledoc false
    use Ash.Domain, validate_config_inclusion?: false

    resources do
      allow_unregistered? true
    end
  end

  describe "validate_write_action/2" do
    test "a write action which doesn't accept the subject attribute fails to compile" do
      error =
        assert_raise Spark.Error.DslError, fn ->
          defmodule AuditLogWithoutSubject do
            @moduledoc false
            use Ash.Resource,
              data_layer: Ash.DataLayer.Ets,
              domain: AshAuthentication.AuditLogResource.TransformerTest.Domain,
              extensions: [AshAuthentication.AuditLogResource]

            actions do
              defaults [:read]

              create :log_activity do
                accept [
                  :id,
                  :strategy,
                  :audit_log,
                  :logged_at,
                  :action_name,
                  :status,
                  :extra_data,
                  :resource
                ]
              end
            end
          end
        end

      assert error.message =~ "Missing:"
      assert error.message =~ ":subject"
    end

    test "a write action which accepts all the required attributes compiles" do
      defmodule AuditLogWithSubject do
        @moduledoc false
        use Ash.Resource,
          data_layer: Ash.DataLayer.Ets,
          domain: AshAuthentication.AuditLogResource.TransformerTest.Domain,
          extensions: [AshAuthentication.AuditLogResource]

        actions do
          defaults [:read]

          create :log_activity do
            accept [
              :id,
              :subject,
              :strategy,
              :audit_log,
              :logged_at,
              :action_name,
              :status,
              :extra_data,
              :resource
            ]
          end
        end
      end

      assert Info.action(AuditLogWithSubject, :log_activity)
    end
  end
end
