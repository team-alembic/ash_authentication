# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.RecoveryCode.Verifier do
  @moduledoc """
  DSL verifier for the recovery_code strategy.
  """
  alias Ash.Resource
  alias AshAuthentication.AddOn.AuditLog.VerifierHelpers
  alias AshAuthentication.Strategy.RecoveryCode
  alias Spark.Dsl.Verifier
  alias Spark.Error.DslError

  @doc false
  @spec verify(RecoveryCode.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl) do
    with :ok <- validate_brute_force_strategy(dsl, strategy),
         :ok <- validate_entropy(dsl, strategy),
         :ok <- validate_code_alphabet(dsl, strategy) do
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
    with {:ok, audit_log} <- VerifierHelpers.validate_audit_log_exists(dsl, strategy, audit_log) do
      VerifierHelpers.validate_action_audit_logged(
        dsl,
        strategy,
        strategy.verify_action_name,
        audit_log
      )
    end
  end

  defp validate_brute_force_strategy(
         dsl,
         %{brute_force_strategy: {:preparation, module}} = strategy
       ) do
    validate_preparation_supports_action_input(dsl, strategy, module)
  end

  defp validate_entropy(dsl, strategy) do
    alphabet_size = String.length(strategy.code_alphabet)
    entropy_bits = strategy.code_length * :math.log2(alphabet_size)
    minimum = strategy.hash_provider.minimum_entropy()

    if entropy_bits >= minimum do
      :ok
    else
      module = Verifier.get_persisted(dsl, :module)

      {:error,
       DslError.exception(
         module: module,
         path: [:authentication, :strategies, strategy.name],
         message: """
         The recovery code configuration provides ~#{Float.round(entropy_bits, 1)} bits of entropy \
         (code_length=#{strategy.code_length}, alphabet_size=#{alphabet_size}), but the hash provider \
         `#{inspect(strategy.hash_provider)}` requires a minimum of #{minimum} bits.

         Either increase `code_length`, use a richer `code_alphabet`, or use a slower hash provider \
         like `AshAuthentication.BcryptProvider`.
         """
       )}
    end
  end

  defp validate_code_alphabet(dsl, strategy) do
    graphemes = String.graphemes(strategy.code_alphabet)
    unique_graphemes = Enum.uniq(graphemes)

    cond do
      length(graphemes) < 2 ->
        module = Verifier.get_persisted(dsl, :module)

        {:error,
         DslError.exception(
           module: module,
           path: [:authentication, :strategies, strategy.name, :code_alphabet],
           message: "The `code_alphabet` must contain at least 2 characters."
         )}

      length(graphemes) != length(unique_graphemes) ->
        module = Verifier.get_persisted(dsl, :module)

        {:error,
         DslError.exception(
           module: module,
           path: [:authentication, :strategies, strategy.name, :code_alphabet],
           message: "The `code_alphabet` must contain only unique characters."
         )}

      true ->
        :ok
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
    case Resource.Info.attribute(resource, strategy.code_field) do
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
    case Resource.Info.relationship(resource, strategy.user_relationship_name) do
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
    if Resource.Info.action(resource, :destroy) do
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
end
