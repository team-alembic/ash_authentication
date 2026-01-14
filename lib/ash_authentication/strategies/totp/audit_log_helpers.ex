# SPDX-FileCopyrightText: 2025 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.AuditLogHelpers do
  @moduledoc """
  Shared helpers for audit log-based brute force protection.

  This module provides common functionality used by both `AuditLogChange` and
  `AuditLogPreparation` to count failed TOTP attempts from the audit log.
  """

  require Ash.Query
  import Ash.Expr

  alias AshAuthentication.AuditLogResource

  @doc """
  Counts failed TOTP attempts for a subject within a time window.

  Queries the audit log resource for entries matching:
  - The given subject (user identifier)
  - Strategy = :totp
  - Status = :failure
  - Logged at or after the cutoff time

  Uses a `FOR UPDATE` lock to prevent race conditions where multiple concurrent
  requests could slip past the brute force limit. While this creates some
  contention, it ensures accurate rate limiting enforcement.

  Returns `{:ok, count}` or `{:error, reason}`.
  """
  @spec count_failures(struct(), String.t(), DateTime.t()) ::
          {:ok, non_neg_integer()} | {:error, any()}
  def count_failures(audit_log, subject, cutoff) do
    audit_log_resource = audit_log.audit_log_resource

    subject_attr = AuditLogResource.Info.audit_log_attributes_subject!(audit_log_resource)
    strategy_attr = AuditLogResource.Info.audit_log_attributes_strategy!(audit_log_resource)
    status_attr = AuditLogResource.Info.audit_log_attributes_status!(audit_log_resource)
    logged_at_attr = AuditLogResource.Info.audit_log_attributes_logged_at!(audit_log_resource)

    query =
      audit_log_resource
      |> Ash.Query.new()
      |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
      |> Ash.Query.filter(^ref(subject_attr) == ^subject)
      |> Ash.Query.filter(^ref(strategy_attr) == :totp)
      |> Ash.Query.filter(^ref(status_attr) == :failure)
      |> Ash.Query.filter(^ref(logged_at_attr) >= ^cutoff)
      # Lock prevents race conditions where concurrent requests slip past the brute force limit
      |> Ash.Query.lock("FOR UPDATE")

    Ash.count(query)
  end
end
