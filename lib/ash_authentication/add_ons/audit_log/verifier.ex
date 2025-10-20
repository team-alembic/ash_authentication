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
         :ok <- verify_exclude_strategies(strategy),
         :ok <- verify_exclude_actions(strategy),
         :ok <- verify_truncation_masks(strategy) do
      verify_sensitive_fields(strategy)
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

  defp verify_truncation_masks(strategy) do
    with :ok <- verify_ipv4_mask(strategy) do
      verify_ipv6_mask(strategy)
    end
  end

  defp verify_ipv4_mask(strategy) do
    mask = Map.get(strategy, :ipv4_truncation_mask, 24)

    if mask >= 0 and mask <= 32 do
      :ok
    else
      {:error,
       DslError.exception(
         module: strategy.resource,
         path: [:authentication, :add_ons, :audit_log, strategy.name, :ipv4_truncation_mask],
         message: "IPv4 truncation mask must be between 0 and 32, got #{mask}"
       )}
    end
  end

  defp verify_ipv6_mask(strategy) do
    mask = Map.get(strategy, :ipv6_truncation_mask, 48)

    if mask >= 0 and mask <= 128 do
      :ok
    else
      {:error,
       DslError.exception(
         module: strategy.resource,
         path: [:authentication, :add_ons, :audit_log, strategy.name, :ipv6_truncation_mask],
         message: "IPv6 truncation mask must be between 0 and 128, got #{mask}"
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

  defp verify_sensitive_fields(strategy) when strategy.include_fields == [], do: :ok

  defp verify_sensitive_fields(strategy) do
    # Find all attributes and action arguments that are sensitive
    attributes = Ash.Resource.Info.attributes(strategy.resource)
    actions = Ash.Resource.Info.actions(strategy.resource)

    # Collect all arguments from all actions
    all_arguments =
      actions
      |> Enum.flat_map(& &1.arguments)
      |> Enum.uniq_by(& &1.name)

    # Find sensitive fields that are being explicitly included
    sensitive_fields_included =
      strategy.include_fields
      |> Enum.filter(fn field_name ->
        # Check if field is a sensitive attribute
        attribute_sensitive? =
          attributes
          |> Enum.find(&(&1.name == field_name))
          |> case do
            nil -> false
            attr -> attr.sensitive?
          end

        # Check if field is a sensitive argument
        argument_sensitive? =
          all_arguments
          |> Enum.find(&(&1.name == field_name))
          |> case do
            nil -> false
            arg -> Map.get(arg, :sensitive?, false)
          end

        attribute_sensitive? || argument_sensitive?
      end)

    if sensitive_fields_included != [] &&
         !Application.get_env(:ash_authentication, :suppress_sensitive_field_warnings?, false) do
      field_list = Enum.map_join(sensitive_fields_included, ", ", &inspect/1)

      IO.warn("""
      AuditLog is configured to log sensitive fields: [#{field_list}]

      Sensitive fields are being explicitly included in audit logs for resource #{inspect(strategy.resource)}.
      This may expose sensitive user data in your audit logs.

      To suppress this warning, add the following to your config:

          config :ash_authentication, suppress_sensitive_field_warnings?: true

      Only suppress this warning if you have verified that logging these sensitive fields is intentional and complies with your security policies.
      """)
    end

    :ok
  end
end
