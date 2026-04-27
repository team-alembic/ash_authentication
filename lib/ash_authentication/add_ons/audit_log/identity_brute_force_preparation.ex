# SPDX-FileCopyrightText: 2025 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog.IdentityBruteForcePreparation do
  @moduledoc """
  Preparation that rejects an action when the audit log shows too many recent
  failed attempts for the submitted identity.

  Used by strategies whose sign-in / request actions take an identity field
  argument (e.g. password sign-in, password reset request, magic-link
  request) when configured with `brute_force_strategy {:audit_log, :my_audit_log}`.

  Unlike `AshAuthentication.AddOn.AuditLog.BruteForcePreparation` — which
  keys on the authenticated user's subject and runs after the action — this
  preparation keys on the identity argument and runs before the action, so
  the check happens without needing to first resolve or load the user.

  The window and maximum are read from the following fields on the strategy
  (both of which mirror the TOTP strategy's DSL options):

  - `audit_log_window` - time window for counting failures.
  - `audit_log_max_failures` - maximum allowed failures before blocking.
  """
  use Ash.Resource.Preparation

  alias Ash.{ActionInput, Query}
  alias AshAuthentication.AddOn.AuditLog.BruteForceHelpers
  alias AshAuthentication.Errors.AuthenticationFailed
  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.Totp.Helpers

  @impl true
  def init(opts), do: {:ok, opts}

  @impl true
  def prepare(query_or_input, opts, context) do
    case query_or_input do
      %Query{} = query ->
        case check(query, opts, context) do
          :ok -> query
          {:error, error} -> Query.add_error(query, error)
        end

      %ActionInput{} = input ->
        case check(input, opts, context) do
          :ok -> input
          {:error, error} -> ActionInput.add_error(input, error)
        end
    end
  end

  @impl true
  def supports(_opts), do: [Query, ActionInput]

  defp check(input, opts, context) do
    with {:ok, strategy} <- Info.find_strategy(input, context, opts),
         {:ok, audit_log} <- audit_log_for(input.resource, strategy),
         identity when is_binary(identity) <- identity_for(input, strategy) do
      enforce_limit(input, strategy, audit_log, identity, opts)
    else
      _ -> :ok
    end
  end

  defp audit_log_for(resource, strategy) do
    case strategy.brute_force_strategy do
      {:audit_log, name} -> Info.strategy(resource, name)
      _ -> :error
    end
  end

  defp identity_for(input, strategy) do
    case Map.get(input.arguments, strategy.identity_field) do
      nil -> nil
      value -> to_string(value)
    end
  end

  defp enforce_limit(input, strategy, audit_log, identity, opts) do
    window = Helpers.time_to_seconds(strategy.audit_log_window)
    max_failures = strategy.audit_log_max_failures
    cutoff = DateTime.add(DateTime.utc_now(), -window, :second)

    case BruteForceHelpers.count_failures(
           audit_log,
           [identity: identity, strategy: strategy.name],
           cutoff
         ) do
      {:ok, count} when count >= max_failures ->
        {:error, too_many_failures_error(input, strategy, opts)}

      {:ok, _} ->
        :ok

      {:error, reason} ->
        {:error, audit_log_unavailable_error(input, strategy, reason, opts)}
    end
  end

  defp too_many_failures_error(_input, strategy, opts) do
    AuthenticationFailed.exception(
      strategy: strategy,
      caused_by: %{
        module: __MODULE__,
        strategy: strategy,
        action: Keyword.get(opts, :action_name, :unknown),
        message: "Too many failed attempts"
      }
    )
  end

  defp audit_log_unavailable_error(_input, strategy, reason, opts) do
    AuthenticationFailed.exception(
      strategy: strategy,
      caused_by: %{
        module: __MODULE__,
        strategy: strategy,
        action: Keyword.get(opts, :action_name, :unknown),
        message: "Audit log unavailable",
        reason: reason
      }
    )
  end
end
