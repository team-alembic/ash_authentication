defmodule AshAuthentication.Strategy.RecoveryCode.Verifier do
  @moduledoc """
  DSL verifier for the recovery_code strategy.
  """
  alias AshAuthentication.Strategy.RecoveryCode
  alias Spark.Dsl.Verifier
  alias Spark.Error.DslError

  @doc false
  @spec verify(RecoveryCode.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl) do
    with :ok <- validate_brute_force_strategy(dsl, strategy),
         :ok <- validate_shared_salt_callbacks(dsl, strategy) do
      validate_recovery_code_resource(dsl, strategy)
    end
  end

  defp validate_brute_force_strategy(dsl, strategy)
       when strategy.brute_force_strategy == :rate_limit do
    with :ok <- validate_rate_limiter_extension(dsl, strategy) do
      validate_verify_rate_limit(dsl, strategy)
    end
  end

  defp validate_brute_force_strategy(
         dsl,
         %{brute_force_strategy: {:audit_log, audit_log}} = strategy
       ) do
    with {:ok, audit_log} <- validate_audit_log_exists(dsl, strategy, audit_log) do
      validate_action_audit_logged(dsl, strategy, strategy.verify_action_name, audit_log)
    end
  end

  defp validate_brute_force_strategy(
         dsl,
         %{brute_force_strategy: {:preparation, module}} = strategy
       ) do
    validate_preparation_supports_action_input(dsl, strategy, module)
  end

  defp validate_shared_salt_callbacks(_dsl, %{use_shared_salt?: false}), do: :ok

  defp validate_shared_salt_callbacks(_dsl, strategy) do
    hash_provider = strategy.hash_provider

    case Code.ensure_loaded(hash_provider) do
      # Module not yet compiled; skip check — will fail at runtime if missing
      {:error, _} -> :ok
      {:module, _} -> check_shared_salt_exports(hash_provider, strategy)
    end
  end

  defp check_shared_salt_exports(hash_provider, strategy) do
    required_callbacks = [gen_salt: 0, hash: 3, extract_salt: 1]

    missing =
      Enum.reject(required_callbacks, fn {fun, arity} ->
        function_exported?(hash_provider, fun, arity)
      end)

    if missing == [] do
      :ok
    else
      missing_str = Enum.map_join(missing, ", ", fn {f, a} -> "#{f}/#{a}" end)

      {:error,
       DslError.exception(
         path: [:authentication, :strategies, strategy.name, :use_shared_salt?],
         message: """
         `use_shared_salt?` is enabled but the hash provider `#{inspect(hash_provider)}` \
         does not implement the required callbacks: #{missing_str}.
         """
       )}
    end
  end

  defp validate_recovery_code_resource(dsl, strategy) do
    resource = strategy.recovery_code_resource
    module = Verifier.get_persisted(dsl, :module)

    with :ok <- validate_code_field(resource, strategy, module),
         :ok <- validate_user_relationship_name(resource, strategy, module) do
      validate_destroy_action(resource, strategy, module)
    end
  end

  defp validate_code_field(resource, strategy, module) do
    case Ash.Resource.Info.attribute(resource, strategy.code_field) do
      nil ->
        {:error,
         DslError.exception(
           module: module,
           path: [:authentication, :strategies, strategy.name, :code_field],
           message: """
           The recovery code resource `#{inspect(resource)}` does not have an attribute named `#{inspect(strategy.code_field)}`.

           Add the attribute to your recovery code resource:

               attribute #{inspect(strategy.code_field)}, :string, sensitive?: true, allow_nil?: false
           """
         )}

      attribute ->
        if attribute.sensitive? do
          :ok
        else
          {:error,
           DslError.exception(
             module: module,
             path: [:authentication, :strategies, strategy.name, :code_field],
             message: """
             The attribute `#{inspect(strategy.code_field)}` on `#{inspect(resource)}` must be marked as `sensitive?: true`.
             """
           )}
        end
    end
  end

  defp validate_user_relationship_name(resource, strategy, module) do
    case Ash.Resource.Info.relationship(resource, strategy.user_relationship_name) do
      nil ->
        {:error,
         DslError.exception(
           module: module,
           path: [:authentication, :strategies, strategy.name, :user_relationship_name],
           message: """
           The recovery code resource `#{inspect(resource)}` does not have a relationship named `#{inspect(strategy.user_relationship_name)}`.

           Add a belongs_to relationship:

               belongs_to #{inspect(strategy.user_relationship_name)}, #{inspect(module)}, allow_nil?: false
           """
         )}

      relationship ->
        if relationship.type == :belongs_to do
          :ok
        else
          {:error,
           DslError.exception(
             module: module,
             path: [:authentication, :strategies, strategy.name, :user_relationship_name],
             message:
               "The relationship `#{inspect(strategy.user_relationship_name)}` on `#{inspect(resource)}` must be a `belongs_to` relationship."
           )}
        end
    end
  end

  defp validate_destroy_action(resource, strategy, module) do
    if Ash.Resource.Info.action(resource, :destroy) do
      :ok
    else
      {:error,
       DslError.exception(
         module: module,
         path: [:authentication, :strategies, strategy.name],
         message: """
         The recovery code resource `#{inspect(resource)}` must have a `:destroy` action.

         Add a destroy action:

             actions do
               defaults [:read, :destroy]
             end
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

  defp validate_verify_rate_limit(dsl, strategy) do
    limited? =
      dsl
      |> Verifier.get_entities([:rate_limit])
      |> Enum.any?(&(&1.action == strategy.verify_action_name))

    if limited? do
      :ok
    else
      module = Verifier.get_persisted(dsl, :module)

      {:error,
       DslError.exception(
         module: module,
         path: [:authentication, :strategies, strategy.name, :brute_force_strategy],
         message: """
         The brute force strategy is set to `:rate_limit` however the `#{inspect(strategy.verify_action_name)}` is not configured with a rate limit.

         See the ash_rate_limiter documentation for more information:
         https://hexdocs.pm/ash_rate_limiter/readme.html
         """
       )}
    end
  end

  defp validate_preparation_supports_action_input(dsl, strategy, module) do
    supported_subjects = get_preparation_supports(module)

    if Ash.ActionInput in supported_subjects do
      :ok
    else
      resource_module = Verifier.get_persisted(dsl, :module)

      {:error,
       DslError.exception(
         module: resource_module,
         path: [:authentication, :strategies, strategy.name, :brute_force_strategy],
         message: """
         The brute force preparation `#{inspect(module)}` does not support `Ash.ActionInput`.

         This is required for the verify (generic action).

         The preparation currently supports: #{inspect(supported_subjects)}

         To fix this, implement the `supports/0` callback in your preparation module:

             @impl true
             def supports, do: [Ash.ActionInput]

         And ensure your `prepare/3` callback can handle ActionInput subjects.
         """
       )}
    end
  end

  defp get_preparation_supports(module) when is_atom(module) do
    module.supports([])
  end

  defp get_preparation_supports({module, opts}) when is_atom(module) do
    module.supports(opts)
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
        {:error,
         DslError.exception(
           module: module,
           path: [:authentication, :strategies, strategy.name, :brute_force_strategy],
           message: """
           The brute force strategy is set to `{:audit_log, #{inspect(audit_log)}}`, however there is no audit-log add-on with that name.
           """
         )}
    end
  end

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
end
