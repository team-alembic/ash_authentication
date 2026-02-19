# SPDX-FileCopyrightText: 2025 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.AuditLogChange do
  @moduledoc """
  Change that checks the audit log for failed TOTP attempts before update actions.

  This is the change variant of `AuditLogPreparation` for use with update actions
  like `confirm_setup`.

  When `brute_force_strategy: {:audit_log, :my_audit_log}` is configured,
  this change queries the audit log for failed TOTP attempts within
  a time window. If the number of failures exceeds the configured maximum,
  the request is denied with an `AuthenticationFailed` error.

  The window and max failures are configured via DSL options:
  - `audit_log_window` - time window for counting failures (default: 5 minutes)
  - `audit_log_max_failures` - maximum allowed failures before blocking (default: 5)

  Failures are counted across ALL TOTP actions (sign_in, verify, confirm_setup)
  for the same user, not per-action.
  """
  use Ash.Resource.Change

  alias Ash.Changeset
  alias AshAuthentication.{Errors.AuthenticationFailed, Info}
  alias AshAuthentication.Strategy.Totp.{AuditLogHelpers, Helpers}

  @impl true
  def init(opts), do: {:ok, opts}

  @impl true
  def change(changeset, opts, context) do
    with {:ok, strategy} <- Info.find_strategy(changeset, context, opts),
         {:ok, audit_log} <- get_audit_log(changeset.resource, strategy),
         user when not is_nil(user) <- changeset.data do
      Changeset.before_action(changeset, &apply_rate_limit(&1, user, strategy, audit_log, opts))
    else
      _ -> changeset
    end
  end

  defp apply_rate_limit(changeset, user, strategy, audit_log, opts) do
    case check_rate_limit(user, strategy, audit_log, opts) do
      :ok -> changeset
      {:error, error} -> Changeset.add_error(changeset, error)
    end
  end

  defp get_audit_log(resource, strategy) do
    case strategy.brute_force_strategy do
      {:audit_log, audit_log_name} ->
        Info.strategy(resource, audit_log_name)

      _ ->
        :error
    end
  end

  defp check_rate_limit(user, strategy, audit_log, opts) do
    subject = AshAuthentication.user_to_subject(user)
    window = Helpers.time_to_seconds(strategy.audit_log_window)
    max_failures = strategy.audit_log_max_failures
    cutoff = DateTime.add(DateTime.utc_now(), -window, :second)

    case AuditLogHelpers.count_failures(audit_log, subject, cutoff) do
      {:ok, failure_count} when failure_count >= max_failures ->
        action_name = Keyword.get(opts, :action_name, :unknown)

        {:error,
         AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: action_name,
             message: "Too many failed TOTP attempts"
           }
         )}

      {:ok, _failure_count} ->
        :ok

      {:error, reason} ->
        {:error,
         AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: Keyword.get(opts, :action_name, :unknown),
             message: "Audit log unavailable",
             reason: reason
           }
         )}
    end
  end
end
