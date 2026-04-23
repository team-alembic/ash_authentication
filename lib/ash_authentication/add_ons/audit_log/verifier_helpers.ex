# SPDX-FileCopyrightText: 2025 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog.VerifierHelpers do
  @moduledoc """
  Helpers for strategy verifiers that need to validate a
  `brute_force_strategy {:audit_log, :name}` configuration against the
  audit-log add-on on the resource.
  """

  alias AshAuthentication.Info
  alias Spark.{Dsl.Verifier, Error.DslError}

  @doc """
  Verify that a strategy of provider `:audit_log` with the given name exists
  on the resource.

  Returns `{:ok, audit_log}` on success, or a `DslError` exception tagged to
  the given strategy's `brute_force_strategy` path on failure.
  """
  @spec validate_audit_log_exists(map, struct, atom) ::
          {:ok, struct} | {:error, Exception.t()}
  def validate_audit_log_exists(dsl_state, strategy, audit_log_name) do
    module = Verifier.get_persisted(dsl_state, :module)

    case Info.strategy(dsl_state, audit_log_name) do
      {:ok, audit_log} when audit_log.provider == :audit_log ->
        {:ok, audit_log}

      {:ok, other_strategy} ->
        {:error,
         DslError.exception(
           module: module,
           path: [:authentication, :strategies, strategy.name, :brute_force_strategy],
           message: """
           The brute force strategy is set to `{:audit_log, #{inspect(audit_log_name)}}`.  There is a strategy named `#{inspect(audit_log_name)}` present, however it is a #{other_strategy.provider} strategy.
           """
         )}

      :error ->
        {:error,
         DslError.exception(
           module: module,
           path: [:authentication, :strategies, strategy.name, :brute_force_strategy],
           message: """
           The brute force strategy is set to `{:audit_log, #{inspect(audit_log_name)}}`, however there is no audit-log add-on with that name.
           """
         )}
    end
  end

  @doc """
  Verify that the given action on the resource is included in the set of
  actions logged by the given audit-log add-on.
  """
  @spec validate_action_audit_logged(map, struct, atom, struct) ::
          :ok | {:error, Exception.t()}
  def validate_action_audit_logged(dsl_state, strategy, action_name, audit_log) do
    logged_actions =
      dsl_state
      |> Verifier.get_persisted({:audit_log, audit_log.name, :actions}, [])
      |> Enum.map(&elem(&1, 0))

    if action_name in logged_actions do
      :ok
    else
      module = Verifier.get_persisted(dsl_state, :module)

      {:error,
       DslError.exception(
         module: module,
         path: [:authentication, :strategies, strategy.name, :brute_force_strategy],
         message: """
         The brute force strategy is set to `{:audit_log, #{inspect(audit_log.name)}}`, however the action `#{inspect(action_name)}` is not logged by that audit log.
         """
       )}
    end
  end
end
