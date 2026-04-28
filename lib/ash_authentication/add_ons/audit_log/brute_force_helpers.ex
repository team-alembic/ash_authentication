# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog.BruteForceHelpers do
  @moduledoc """
  Helpers for audit log-based brute force protection.

  Provides shared functionality for counting failed authentication attempts
  from the audit log. Used by the TOTP, recovery code, password and magic
  link strategies when configured with `brute_force_strategy {:audit_log,
  :audit_log}`.
  """

  require Ash.Query
  import Ash.Expr

  alias AshAuthentication.AuditLogResource

  @type criteria :: [
          {:subject, String.t()} | {:identity, String.t()} | {:strategy, atom()}
        ]

  @doc """
  Counts failed attempts for a subject and strategy within a time window.

  See `count_failures/3` for the more general form.
  """
  @spec count_failures(struct(), String.t(), atom(), DateTime.t()) ::
          {:ok, non_neg_integer()} | {:error, any()}
  def count_failures(audit_log, subject, strategy_name, cutoff) do
    count_failures(audit_log, [subject: subject, strategy: strategy_name], cutoff)
  end

  @doc """
  Counts failed attempts matching the given criteria within a time window.

  `criteria` is a keyword list that may contain any of:
  - `:subject` - the user's authentication subject
  - `:identity` - the submitted identity (e.g. email or username)
  - `:strategy` - the strategy name

  The audit log entries must additionally have `status == :failure` and have
  been `logged_at` at or after the given cutoff.

  Uses a `FOR UPDATE` lock to prevent race conditions where multiple concurrent
  requests could slip past the brute force limit.

  Returns `{:ok, count}` or `{:error, reason}`.
  """
  @spec count_failures(struct(), criteria, DateTime.t()) ::
          {:ok, non_neg_integer()} | {:error, any()}
  def count_failures(audit_log, criteria, cutoff) when is_list(criteria) do
    audit_log_resource = audit_log.audit_log_resource

    status_attr = AuditLogResource.Info.audit_log_attributes_status!(audit_log_resource)
    logged_at_attr = AuditLogResource.Info.audit_log_attributes_logged_at!(audit_log_resource)

    audit_log_resource
    |> Ash.Query.new()
    |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
    |> apply_criteria(audit_log_resource, criteria)
    |> Ash.Query.filter(^ref(status_attr) == :failure)
    |> Ash.Query.filter(^ref(logged_at_attr) >= ^cutoff)
    |> Ash.Query.lock("FOR UPDATE")
    |> Ash.count()
  end

  defp apply_criteria(query, audit_log_resource, criteria) do
    Enum.reduce(criteria, query, fn
      {:subject, value}, query ->
        attr = AuditLogResource.Info.audit_log_attributes_subject!(audit_log_resource)
        Ash.Query.filter(query, ^ref(attr) == ^value)

      {:identity, value}, query ->
        attr = AuditLogResource.Info.audit_log_attributes_identity!(audit_log_resource)
        Ash.Query.filter(query, ^ref(attr) == ^value)

      {:strategy, value}, query ->
        attr = AuditLogResource.Info.audit_log_attributes_strategy!(audit_log_resource)
        Ash.Query.filter(query, ^ref(attr) == ^value)
    end)
  end
end
