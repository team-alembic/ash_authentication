defmodule AshAuthentication.Strategy.RecoveryCode.Transformer do
  @moduledoc """
  DSL transformer for the recovery_code strategy.
  """
  alias AshAuthentication.Strategy
  alias AshAuthentication.Strategy.RecoveryCode
  alias Spark.Dsl.Transformer
  alias Spark.Error.DslError

  import AshAuthentication.Strategy.Custom.Helpers
  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action

  @doc false
  @spec transform(RecoveryCode.t(), map) ::
          {:ok, RecoveryCode.t() | map} | {:error, Exception.t()}
  def transform(strategy, dsl) do
    with strategy <- transform_audit_log_window(strategy),
         :ok <- validate_recovery_codes_relationship(strategy, dsl),
         {:ok, dsl, strategy} <- handle_verify_action(dsl, strategy),
         {:ok, dsl, strategy} <- handle_generate_action(dsl, strategy),
         {:ok, resource} <- persisted_option(dsl, :module) do
      strategy = %{strategy | resource: resource}

      action_names =
        [strategy.verify_action_name]
        |> maybe_append(strategy.generate_enabled?, strategy.generate_action_name)

      dsl = register_strategy_actions(action_names, dsl, strategy)

      {:ok,
       Transformer.replace_entity(
         dsl,
         [:authentication, :strategies],
         strategy,
         &(Strategy.name(&1) == strategy.name)
       )}
    end
  end

  defp transform_audit_log_window(strategy) when is_integer(strategy.audit_log_window),
    do: %{strategy | audit_log_window: strategy.audit_log_window * 60}

  defp transform_audit_log_window(strategy) when is_tuple(strategy.audit_log_window) do
    {value, unit} = strategy.audit_log_window

    seconds =
      case unit do
        :days -> value * 24 * 60 * 60
        :hours -> value * 60 * 60
        :minutes -> value * 60
        :seconds -> value
      end

    %{strategy | audit_log_window: seconds}
  end

  defp validate_recovery_codes_relationship(strategy, dsl) do
    case find_relationship(dsl, strategy.recovery_codes_relationship_name) do
      {:ok, relationship} ->
        if relationship.type == :has_many do
          :ok
        else
          module = Transformer.get_persisted(dsl, :module)

          {:error,
           DslError.exception(
             module: module,
             path: [
               :authentication,
               :strategies,
               :recovery_code,
               strategy.name,
               :recovery_codes_relationship_name
             ],
             message:
               "The relationship `#{inspect(strategy.recovery_codes_relationship_name)}` must be a `has_many` relationship."
           )}
        end

      :error ->
        module = Transformer.get_persisted(dsl, :module)

        {:error,
         DslError.exception(
           module: module,
           path: [
             :authentication,
             :strategies,
             :recovery_code,
             strategy.name,
             :recovery_codes_relationship_name
           ],
           message: """
           The relationship `#{inspect(strategy.recovery_codes_relationship_name)}` does not exist on this resource.

           Add a has_many relationship:

               relationships do
                 has_many #{inspect(strategy.recovery_codes_relationship_name)}, YourApp.RecoveryCode
               end
           """
         )}
    end
  end

  # sobelow_skip ["DOS.BinToAtom"]
  defp handle_verify_action(dsl, strategy) when is_nil(strategy.verify_action_name),
    do:
      handle_verify_action(dsl, %{strategy | verify_action_name: :"verify_with_#{strategy.name}"})

  defp handle_verify_action(dsl, strategy) do
    with {:ok, dsl} <-
           maybe_build_action(
             dsl,
             strategy.verify_action_name,
             &build_verify_action(&1, strategy)
           ),
         :ok <- validate_verify_action(dsl, strategy) do
      {:ok, dsl, strategy}
    end
  end

  defp build_verify_action(dsl, strategy) do
    module = Transformer.get_persisted(dsl, :module)

    arguments = [
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :action], :argument,
        name: :user,
        type: Ash.Type.Struct,
        allow_nil?: false,
        description: "The user to verify the recovery code for.",
        constraints: [instance_of: module]
      ),
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :action], :argument,
        name: :code,
        type: Ash.Type.String,
        allow_nil?: false,
        sensitive?: true,
        description: "The recovery code to verify."
      )
    ]

    preparations =
      case strategy.brute_force_strategy do
        {:preparation, preparation} ->
          [
            Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :action], :prepare,
              preparation: preparation
            )
          ]

        {:audit_log, _audit_log_name} ->
          [
            Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :action], :prepare,
              preparation:
                {AshAuthentication.Strategy.Totp.AuditLogPreparation,
                 action_name: strategy.verify_action_name}
            )
          ]

        _ ->
          []
      end

    touches_resources =
      with {:audit_log, audit_log} <- strategy.brute_force_strategy,
           {:ok, audit_log} <- AshAuthentication.Info.strategy(dsl, audit_log) do
        Enum.uniq([module, strategy.recovery_code_resource, audit_log.audit_log_resource])
      else
        _ -> [module, strategy.recovery_code_resource]
      end

    Transformer.build_entity(Ash.Resource.Dsl, [:actions], :action,
      name: strategy.verify_action_name,
      arguments: arguments,
      returns: :term,
      transaction?: true,
      description: "Verify a recovery code and return the user if valid, nil otherwise.",
      touches_resources: touches_resources,
      run: AshAuthentication.Strategy.RecoveryCode.VerifyAction,
      preparations: preparations
    )
  end

  defp validate_verify_action(dsl, strategy) do
    module = Transformer.get_persisted(dsl, :module)

    with {:ok, action} <- validate_action_exists(dsl, strategy.verify_action_name),
         :ok <- validate_action_has_argument(action, :code),
         :ok <- validate_action_has_argument(action, :user),
         :ok <- validate_action_argument_option(action, :code, :type, [Ash.Type.String, :string]),
         :ok <- validate_action_argument_option(action, :code, :allow_nil?, [false]),
         :ok <- validate_action_argument_option(action, :user, :type, [Ash.Type.Struct, :struct]),
         :ok <- validate_action_argument_option(action, :user, :allow_nil?, [false]),
         :ok <-
           validate_action_option(action, :run, [
             {AshAuthentication.Strategy.RecoveryCode.VerifyAction, []}
           ]),
         :ok <- validate_strategy_preparation(action, strategy.brute_force_strategy) do
      constraints =
        action.arguments
        |> Enum.find(%{}, &(&1.name == :user))
        |> Map.get(:constraints, [])

      if constraints[:instance_of] == module do
        :ok
      else
        {:error,
         DslError.exception(
           module: module,
           path: [:actions, :action, strategy.verify_action_name, :arguments, :user],
           message: "The argument should have the constraint `[instance_of: #{inspect(module)}]`"
         )}
      end
    end
  end

  defp handle_generate_action(dsl, strategy) when strategy.generate_enabled? != true,
    do: {:ok, dsl, strategy}

  # sobelow_skip ["DOS.BinToAtom"]
  defp handle_generate_action(dsl, strategy) when is_nil(strategy.generate_action_name),
    do:
      handle_generate_action(dsl, %{
        strategy
        | generate_action_name: :"generate_#{strategy.name}_codes"
      })

  defp handle_generate_action(dsl, strategy) do
    with {:ok, dsl} <-
           maybe_build_action(
             dsl,
             strategy.generate_action_name,
             &build_generate_action(&1, strategy)
           ),
         :ok <- validate_generate_action(dsl, strategy) do
      {:ok, dsl, strategy}
    end
  end

  defp build_generate_action(_dsl, strategy) do
    arguments = [
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :update], :argument,
        name: :recovery_codes,
        type: {:array, :string},
        allow_nil?: false,
        public?: false,
        sensitive?: true,
        default:
          {AshAuthentication.Strategy.RecoveryCode.Actions, :generate_codes_list,
           [strategy.code_length, strategy.recovery_code_count]}
      )
    ]

    changes = [
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :update], :change,
        change:
          {Ash.Resource.Change.CascadeDestroy,
           relationship: strategy.recovery_codes_relationship_name, after_action?: false}
      ),
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :update], :change,
        change:
          {AshAuthentication.Strategy.RecoveryCode.HashRecoveryCodesChange,
           hash_provider: strategy.hash_provider, use_shared_salt?: strategy.use_shared_salt?}
      ),
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :update], :change,
        change:
          {Ash.Resource.Change.ManageRelationship,
           argument: :recovery_codes,
           relationship: strategy.recovery_codes_relationship_name,
           opts: [type: :create, value_is_key: strategy.code_field]}
      )
    ]

    metadata = [
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :update], :metadata,
        name: :recovery_codes,
        type: {:array, :string},
        allow_nil?: false
      )
    ]

    Transformer.build_entity(Ash.Resource.Dsl, [:actions], :update,
      name: strategy.generate_action_name,
      arguments: arguments,
      changes: changes,
      metadata: metadata,
      accept: [],
      require_atomic?: false,
      touches_resources: [strategy.recovery_code_resource],
      description: "Generate new recovery codes for the user, replacing any existing codes."
    )
  end

  defp validate_generate_action(dsl, strategy) do
    with {:ok, action} <- validate_action_exists(dsl, strategy.generate_action_name) do
      validate_action_has_argument(action, :recovery_codes)
    end
  end

  defp validate_strategy_preparation(action, {:preparation, preparation}),
    do: validate_action_has_preparation(action, preparation)

  defp validate_strategy_preparation(action, {:audit_log, _audit_log_name}),
    do:
      validate_action_has_preparation(action, AshAuthentication.Strategy.Totp.AuditLogPreparation)

  defp validate_strategy_preparation(_, _), do: :ok
end
