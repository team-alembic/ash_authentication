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
      describe: """
      Adds automatic audit logging for authentication events.

      The audit log add-on records all authentication-related events (sign in, registration, password reset, etc.)
      to a dedicated audit log resource. This provides a comprehensive security trail that can be used for
      compliance, security monitoring, and user activity analysis.

      Events are batched for performance and automatically expire based on configured retention periods.
      Sensitive fields are filtered by default but can be explicitly included when necessary.
      IP addresses can be transformed for privacy compliance using hashing, truncation, or exclusion.
      """,
      examples: [
        """
        audit_log do
          audit_log_resource MyApp.Accounts.AuditLog
          include_strategies [:password, :oauth2]
          exclude_actions [:sign_in_with_token]
          ip_privacy_mode :truncate
          ipv4_truncation_mask 24
          ipv6_truncation_mask 48
        end
        """
      ],
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
        include_strategies: [
          doc: "Explicitly allow events from the named strategies.",
          default: [:*]
        ],
        include_actions: [
          doc: "Explicitly allow events from the named actions.",
          default: [:*]
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
        ],
        ip_privacy_mode: [
          type: {:in, [:none, :hash, :truncate, :exclude]},
          required: false,
          default: :none,
          doc:
            "How to handle IP addresses for privacy - :none (store as-is), :hash (SHA256), :truncate (network prefix), or :exclude (don't store)."
        ],
        ipv4_truncation_mask: [
          type: :pos_integer,
          required: false,
          default: 24,
          doc: "IPv4 network mask bits for truncation (0-32). Default 24 keeps first 3 octets."
        ],
        ipv6_truncation_mask: [
          type: :pos_integer,
          required: false,
          default: 48,
          doc:
            "IPv6 network prefix bits for truncation (0-128). Default 48 keeps first 3 segments."
        ]
      ]
    }
  end
end
