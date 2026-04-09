# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog.BruteForceHelpers do
  @moduledoc """
  Helpers for audit log-based brute force protection.

  Provides shared functionality for counting failed authentication attempts
  from the audit log. Used by the TOTP and recovery code strategies when
  configured with `brute_force_strategy {:audit_log, :audit_log}`.
  """

  require Ash.Query
  import Ash.Expr

  alias AshAuthentication.AuditLogResource

  @doc """
  Counts failed attempts for a subject and strategy within a time window.

  Queries the audit log resource for entries matching:
  - The given subject (user identifier)
  - The given strategy name
  - Status = :failure
  - Logged at or after the cutoff time

  Uses a `FOR UPDATE` lock to prevent race conditions where multiple concurrent
  requests could slip past the brute force limit.

  Returns `{:ok, count}` or `{:error, reason}`.
  """
  @spec count_failures(struct(), String.t(), atom(), DateTime.t()) ::
          {:ok, non_neg_integer()} | {:error, any()}
  def count_failures(audit_log, subject, strategy_name, cutoff) do
    audit_log_resource = audit_log.audit_log_resource

    subject_attr = AuditLogResource.Info.audit_log_attributes_subject!(audit_log_resource)
    strategy_attr = AuditLogResource.Info.audit_log_attributes_strategy!(audit_log_resource)
    status_attr = AuditLogResource.Info.audit_log_attributes_status!(audit_log_resource)
    logged_at_attr = AuditLogResource.Info.audit_log_attributes_logged_at!(audit_log_resource)

    audit_log_resource
    |> Ash.Query.new()
    |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
    |> Ash.Query.filter(^ref(subject_attr) == ^subject)
    |> Ash.Query.filter(^ref(strategy_attr) == ^strategy_name)
    |> Ash.Query.filter(^ref(status_attr) == :failure)
    |> Ash.Query.filter(^ref(logged_at_attr) >= ^cutoff)
    |> Ash.Query.lock("FOR UPDATE")
    |> Ash.count()
  end
end
