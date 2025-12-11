# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.Verifier do
  @moduledoc """
  DSL verifier for the totp strategy.
  """
  alias AshAuthentication.Strategy.Totp
  alias Spark.Dsl.Verifier
  alias Spark.Error.DslError

  @doc false
  @spec verify(Totp.t(), map) :: {:ok, Totp.t() | map} | {:error, Exception.t()}
  def verify(strategy, dsl) do
    validate_brute_force_strategy(dsl, strategy)
  end

  defp validate_brute_force_strategy(dsl, strategy)
       when strategy.brute_force_strategy == :rate_limit do
    with :ok <- validate_rate_limiter_extension(dsl, strategy),
         :ok <- maybe_validate_verify_rate_limit(dsl, strategy),
         :ok <- maybe_validate_confirm_setup_rate_limit(dsl, strategy) do
      maybe_validate_sign_in_rate_limit(dsl, strategy)
    end
  end

  defp validate_brute_force_strategy(
         dsl,
         %{brute_force_strategy: {:audit_log, audit_log}} = strategy
       ) do
    with {:ok, audit_log} <- validate_audit_log_exists(dsl, strategy, audit_log),
         :ok <- maybe_validate_confirm_setup_audit_log(dsl, strategy, audit_log) do
      maybe_validate_sign_in_audit_log(dsl, strategy, audit_log)
    end
  end

  defp validate_brute_force_strategy(_dsl, %{brute_force_strategy: {:predicate, _module}}),
    do: :ok

  defp validate_brute_force_strategy(_dsl, %{brute_force_strategy: {:preparation, _module}}),
    do: :ok

  defp maybe_validate_confirm_setup_audit_log(dsl, strategy, audit_log)
       when strategy.confirm_setup_enabled?,
       do:
         validate_action_audit_logged(
           dsl,
           strategy,
           strategy.confirm_setup_action_name,
           audit_log
         )

  defp maybe_validate_confirm_setup_audit_log(_, _, _), do: :ok

  defp maybe_validate_sign_in_audit_log(dsl, strategy, audit_log) when strategy.sign_in_enabled?,
    do: validate_action_audit_logged(dsl, strategy, strategy.sign_in_action_name, audit_log)

  defp maybe_validate_sign_in_audit_log(_, _, _), do: :ok

  defp validate_action_audit_logged(dsl, strategy, action, audit_log) do
    logged_actions =
      dsl
      |> Verifier.get_persisted({:audit_log, audit_log.name, :actions}, [])
      |> Enum.map(&elem(&1, 0))

    if action in logged_actions do
      :ok
    else
      module = Verifier.get_persisted(dsl, :module)

      {:error,
       DslError.exception(
         module: module,
         path: [:authentication, :strategies, strategy.name, :brute_force_strategy],
         message: """
         The brute force strategy is set to `{:audit_log, #{inspect(audit_log)}}`, however the action `#{inspect(action)}` is not logged by that audit log.
         """
       )}
    end
  end

  defp validate_rate_limiter_extension(dsl, strategy) do
    if AshRateLimiter in Spark.extensions(dsl) do
      :ok
    else
      module = Verifier.get_persisted(dsl, :module)

      {:error,
       DslError.exception(
         module: module,
         path: [:authentication, :strategies, strategy.name, :brute_force_strategy],
         message: """
         The brute force strategy is set to `:rate_limit` however the `AshRateLimiter` extension is not present on this resource.
         """
       )}
    end
  end

  defp maybe_validate_verify_rate_limit(dsl, strategy) when strategy.verify_enabled?,
    do: validate_action_rate_limit(dsl, strategy, strategy.verify_action_name)

  defp maybe_validate_verify_rate_limit(_dsl, _strategy), do: :ok

  defp maybe_validate_confirm_setup_rate_limit(dsl, strategy)
       when strategy.confirm_setup_enabled?,
       do: validate_action_rate_limit(dsl, strategy, strategy.confirm_setup_action_name)

  defp maybe_validate_confirm_setup_rate_limit(_dsl, _strategy), do: :ok

  defp maybe_validate_sign_in_rate_limit(dsl, strategy) when strategy.sign_in_enabled?,
    do: validate_action_rate_limit(dsl, strategy, strategy.sign_in_action_name)

  defp maybe_validate_sign_in_rate_limit(_, _), do: :ok

  defp validate_action_rate_limit(dsl, strategy, action_name) do
    limited? =
      dsl
      |> Verifier.get_entities([:rate_limit])
      |> Enum.any?(&(&1.action == action_name))

    if limited? do
      :ok
    else
      module = Verifier.get_persisted(dsl, :module)

      {:error,
       DslError.exception(
         module: module,
         path: [:authentication, :strategies, strategy.name, :brute_force_strategy],
         message: """
         The brute force strategy is set to `:rate_limit` however the `#{inspect(action_name)}` is not configured with a rate limit.

         See the ash_rate_limiter documentation for more information:
         https://hexdocs.pm/ash_rate_limiter/readme.html
         """
       )}
    end
  end

  defp validate_audit_log_exists(dsl, strategy, audit_log) do
    module = Verifier.get_persisted(dsl, :module)

    case AshAuthentication.Info.strategy(dsl, audit_log) do
      {:ok, audit_log} when audit_log.provider == :audit_log ->
        {:ok, audit_log}

      {:ok, other_strategy} ->
        {:error,
         DslError.exception(
           module: module,
           path: [:authentication, :strategies, strategy.name, :brute_force_strategy],
           message: """
           The brute force strategy is set to `{:audit_log, #{inspect(audit_log)}}`.  There is a strategy named `#{inspect(audit_log)}` present, however it is a #{other_strategy.provider} strategy.
           """
         )}

      :error ->
        {
          :error,
          DslError.exception(
            module: module,
            path: [:authentication, :strategies, strategy.name, :brute_force_strategy],
            message: """
            The brute force strategy is set to `{:audit_log, #{inspect(audit_log)}}`, however there is no audit-log add-on with that name.
            """
          )
        }
    end
  end
end
