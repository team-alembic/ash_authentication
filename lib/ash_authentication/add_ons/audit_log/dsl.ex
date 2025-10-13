# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog.Dsl do
  @moduledoc """
  Defines the Spark DSL entity for this add on.
  """
  alias AshAuthentication.AddOn.AuditLog

  @doc false
  @spec dsl :: map
  def dsl do
    %Spark.Dsl.Entity{
      name: :audit_log,
      describe: "Audit log add-on",
      args: [{:optional, :name, :audit_log}],
      target: AuditLog,
      schema: [
        name: [
          type: :atom,
          doc: "Uniquely identifies the add-on.",
          required: true
        ],
        audit_log_resource: [
          type: {:spark, Ash.Resource},
          doc: "The name of the Audit Log resource.",
          required: true
        ],
        exclude_strategies: [
          type: {:wrap_list, :atom},
          doc: "Explicitly ignore events from the named strategies.",
          default: []
        ],
        exclude_actions: [
          type: {:wrap_list, :atom},
          doc: "Explicitly ignore events from the named actions.",
          default: []
        ],
        include_fields: [
          type: {:wrap_list, :atom},
          required: false,
          default: [],
          doc:
            "Explicitly include named attributes and arguments in the audit log regardless of their sensitivity setting."
        ]
      ]
    }
  end
end
