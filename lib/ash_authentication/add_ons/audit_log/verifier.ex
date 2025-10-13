# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.AuditLog.Verifier do
  @moduledoc """
  Provides configuration validation for the AuditLog add-on.
  """

  alias Spark.Error.DslError

  @doc false
  def verify(strategy, _dsl) do
    with :ok <- verify_audit_log_resource(strategy),
         :ok <- verify_exclude_strategies(strategy) do
      verify_exclude_actions(strategy)
    end
  end

  defp verify_audit_log_resource(strategy) do
    cond do
      !Spark.Dsl.is?(strategy.audit_log_resource, Ash.Resource) ->
        {:error,
         DslError.exception(
           module: strategy.resource,
           path: [:authentication, :add_ons, :audit_log, strategy.name, :audit_log_resource],
           message: "The module `#{inspect(strategy.audit_log_resource)}` is not an Ash resource."
         )}

      AshAuthentication.AuditLogResource not in Spark.extensions(strategy.audit_log_resource) ->
        {:error,
         DslError.exception(
           module: strategy.resource,
           path: [:authentication, :add_ons, :audit_log, strategy.name, :audit_log_resource],
           message:
             "The resource `#{inspect(strategy.audit_log_resource)}` must use the `AshAuthentication.AuditLogResource` extension."
         )}

      true ->
        :ok
    end
  end

  defp verify_exclude_strategies(strategy) when strategy.exclude_strategies == [], do: :ok

  defp verify_exclude_strategies(strategy) do
    strategy.exclude_strategies
    |> Enum.reject(&AshAuthentication.Info.strategy_present?(strategy.resource, &1))
    |> case do
      [] ->
        :ok

      [missing_strategy] ->
        {:error,
         DslError.exception(
           module: strategy.resource,
           path: [:authentication, :add_ons, :audit_log, strategy.name, :exclude_strategies],
           message:
             "The strategy or add-on `#{inspect(missing_strategy)}` is not present on the resource `#{inspect(strategy.resource)}`."
         )}

      missing_strategies ->
        missing_strategies = Enum.map_join(missing_strategies, "\n  - ", &"`#{inspect(&1)}`")

        {:error,
         DslError.exception(
           module: strategy.resource,
           path: [:authentication, :add_ons, :audit_log, strategy.name, :exclude_strategies],
           message: """
           The following strategies or add-ons are not present on the resource `#{inspect(strategy.resource)}`:

           - #{missing_strategies}
           """
         )}
    end
  end

  defp verify_exclude_actions(strategy) when strategy.exclude_actions == [], do: :ok

  defp verify_exclude_actions(strategy) do
    strategy.exclude_actions
    |> Enum.reject(&Ash.Resource.Info.action(strategy.resource, &1))
    |> case do
      [] ->
        :ok

      [missing_action] ->
        {:error,
         DslError.exception(
           module: strategy.resource,
           path: [:authentication, :add_ons, :audit_log, strategy.name, :exclude_actions],
           message:
             "The action `#{inspect(missing_action)}` is not present on the resource `#{inspect(strategy.resource)}`."
         )}

      missing_actions ->
        missing_actions = Enum.map_join(missing_actions, "\n  - ", &"`#{inspect(&1)}`")

        {:error,
         DslError.exception(
           module: strategy.resource,
           path: [:authentication, :add_ons, :audit_log, strategy.name, :exclude_actions],
           message: """
           The following actions are not present on the resource `#{inspect(strategy.resource)}`:

           - #{missing_actions}
           """
         )}
    end
  end
end
