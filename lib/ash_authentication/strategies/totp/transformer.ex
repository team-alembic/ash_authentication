# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.Transformer do
  @moduledoc """
  DSL transformer for the totp strategy.
  """
  alias AshAuthentication.Strategy
  alias AshAuthentication.Strategy.Totp
  alias Spark.Dsl.Transformer
  alias Spark.Error.DslError

  import AshAuthentication.Strategy.Custom.Helpers
  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action
  import AshAuthentication.Validations.Attribute

  @doc false
  @spec transform(Totp.t(), map) :: {:ok, Totp.t() | map} | {:error, Exception.t()}
  def transform(strategy, dsl) do
    with strategy <- maybe_set_field_lazy(strategy, :issuer, &to_string(&1.name)),
         strategy <- maybe_set_field_lazy(strategy, :read_secret_from, & &1.secret_field),
         strategy <- transform_setup_token_lifetime(strategy),
         strategy <- transform_audit_log_window(strategy),
         :ok <- validate_identity_field(strategy.identity_field, dsl),
         :ok <- validate_secret_field(strategy.secret_field, dsl),
         :ok <- validate_last_totp_at_field(strategy.last_totp_at_field, dsl),
         :ok <- validate_confirm_setup_requirements(strategy, dsl),
         :ok <- validate_confirm_setup_requires_setup(strategy, dsl),
         :ok <- warn_period_range(strategy, dsl),
         :ok <- warn_secret_length(strategy, dsl),
         {:ok, dsl, strategy} <- handle_setup_action(dsl, strategy),
         {:ok, dsl, strategy} <- handle_confirm_setup_action(dsl, strategy),
         {:ok, dsl, strategy} <- handle_sign_in_action(dsl, strategy),
         {:ok, dsl, strategy} <- handle_verify_action(dsl, strategy),
         {:ok, dsl} <- handle_totp_url_calculation(dsl, strategy),
         {:ok, resource} <- persisted_option(dsl, :module) do
      strategy = %{strategy | resource: resource}

      dsl =
        [
          strategy.setup_enabled? && strategy.setup_action_name,
          strategy.confirm_setup_enabled? && strategy.confirm_setup_action_name,
          strategy.sign_in_enabled? && strategy.sign_in_action_name,
          strategy.verify_enabled? && strategy.verify_action_name
        ]
        |> Enum.reject(&(!&1))
        |> register_strategy_actions(dsl, strategy)

      {:ok,
       Transformer.replace_entity(
         dsl,
         [:authentication, :strategies],
         strategy,
         &(Strategy.name(&1) == strategy.name)
       )}
    end
  end

  defp validate_identity_field(identity_field, dsl) do
    with {:ok, resource} <- persisted_option(dsl, :module),
         {:ok, attribute} <- find_attribute(dsl, identity_field),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :public?, [true]) do
      validate_attribute_unique_constraint(dsl, [identity_field], resource)
    end
  end

  defp validate_secret_field(secret_field, dsl) do
    with {:ok, resource} <- persisted_option(dsl, :module),
         {:ok, attribute} <- find_attribute(dsl, secret_field),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :sensitive?, [true]) do
      validate_attribute_option(attribute, resource, :public?, [false])
    end
  end

  defp transform_setup_token_lifetime(strategy) when is_integer(strategy.setup_token_lifetime),
    do: %{strategy | setup_token_lifetime: strategy.setup_token_lifetime * 60}

  defp transform_setup_token_lifetime(strategy)
       when is_tuple(strategy.setup_token_lifetime) do
    {value, unit} = strategy.setup_token_lifetime

    seconds =
      case unit do
        :days -> value * 24 * 60 * 60
        :hours -> value * 60 * 60
        :minutes -> value * 60
        :seconds -> value
      end

    %{strategy | setup_token_lifetime: seconds}
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

  defp validate_confirm_setup_requirements(strategy, _dsl)
       when strategy.confirm_setup_enabled? != true,
       do: :ok

  defp validate_confirm_setup_requirements(strategy, dsl) do
    if AshAuthentication.Info.authentication_tokens_enabled?(dsl) do
      :ok
    else
      {:error,
       DslError.exception(
         module: Transformer.get_persisted(dsl, :module),
         path: [:authentication, :strategies, :totp, strategy.name],
         message: """
         The `confirm_setup_enabled?` option requires tokens to be enabled.

         Please add a `tokens` section to your authentication configuration:

             authentication do
               tokens do
                 enabled? true
                 token_resource YourApp.Accounts.Token
               end
             end
         """
       )}
    end
  end

  defp validate_confirm_setup_requires_setup(strategy, dsl) do
    if strategy.confirm_setup_enabled? and not strategy.setup_enabled? do
      {:error,
       DslError.exception(
         module: Transformer.get_persisted(dsl, :module),
         path: [:authentication, :strategies, :totp, strategy.name],
         message: """
         The `confirm_setup_enabled?` option requires `setup_enabled?` to be true.

         Either enable setup:

             totp :totp do
               setup_enabled? true
               confirm_setup_enabled? true
             end

         Or disable confirm_setup:

             totp :totp do
               confirm_setup_enabled? false
             end
         """
       )}
    else
      :ok
    end
  end

  defp warn_period_range(strategy, dsl) do
    module = Transformer.get_persisted(dsl, :module)

    cond do
      strategy.period < 15 ->
        IO.warn("""
        TOTP period #{strategy.period}s is very short for #{inspect(module)}.
        Consider at least 15 seconds. Very short periods may cause clock synchronisation issues.
        """)

        :ok

      strategy.period > 300 ->
        IO.warn("""
        TOTP period #{strategy.period}s is very long for #{inspect(module)}.
        Consider at most 300 seconds. Long periods increase the attack window for stolen codes.
        """)

        :ok

      true ->
        :ok
    end
  end

  defp warn_secret_length(strategy, dsl) do
    if strategy.secret_length < 16 do
      module = Transformer.get_persisted(dsl, :module)

      IO.warn("""
      TOTP secret_length #{strategy.secret_length} bytes is below RFC 4226 recommendation for #{inspect(module)}.
      The RFC recommends at least 16 bytes (128 bits) for security.
      """)
    end

    :ok
  end

  defp handle_setup_action(dsl, strategy) when strategy.setup_enabled? != true,
    do: {:ok, dsl, strategy}

  # sobelow_skip ["DOS.BinToAtom"]
  defp handle_setup_action(dsl, strategy) when is_nil(strategy.setup_action_name),
    do: handle_setup_action(dsl, %{strategy | setup_action_name: :"setup_with_#{strategy.name}"})

  defp handle_setup_action(dsl, strategy) do
    with {:ok, dsl} <-
           maybe_build_action(dsl, strategy.setup_action_name, &build_setup_action(&1, strategy)),
         :ok <- validate_setup_action(dsl, strategy) do
      {:ok, dsl, strategy}
    end
  end

  defp build_setup_action(_dsl, strategy) when strategy.confirm_setup_enabled? do
    changes = [
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :update], :change,
        change: AshAuthentication.Strategy.Totp.GeneratePendingSetupChange,
        description:
          "Generate a new TOTP secret, store it in a setup token, and return the setup_token and totp_url in metadata."
      )
    ]

    metadata = [
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :update], :metadata,
        name: :setup_token,
        type: :string,
        allow_nil?: false,
        description: "A JWT token containing the pending TOTP secret."
      ),
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :update], :metadata,
        name: :totp_url,
        type: :string,
        allow_nil?: false,
        description: "The TOTP URL for generating a QR code."
      )
    ]

    Transformer.build_entity(Ash.Resource.Dsl, [:actions], :update,
      name: strategy.setup_action_name,
      accept: [],
      changes: changes,
      metadata: metadata,
      require_atomic?: false,
      description:
        "Generate a pending TOTP secret and return a setup token. Use the confirm_setup action to activate."
    )
  end

  defp build_setup_action(_dsl, strategy) do
    changes = [
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :update], :change,
        change: AshAuthentication.Strategy.Totp.GenerateSecretChange,
        description:
          "Generate a new TOTP secret and store it in the `#{inspect(strategy.secret_field)}` attribute."
      )
    ]

    Transformer.build_entity(Ash.Resource.Dsl, [:actions], :update,
      name: strategy.setup_action_name,
      accept: [],
      changes: changes,
      require_atomic?: false,
      description:
        "Generate a new TOTP secret and store it in the `#{inspect(strategy.secret_field)}` attribute."
    )
  end

  defp validate_setup_action(dsl, strategy) when strategy.confirm_setup_enabled? do
    with {:ok, action} <- validate_action_exists(dsl, strategy.setup_action_name) do
      validate_action_has_change(
        action,
        AshAuthentication.Strategy.Totp.GeneratePendingSetupChange
      )
    end
  end

  defp validate_setup_action(dsl, strategy) do
    with {:ok, action} <- validate_action_exists(dsl, strategy.setup_action_name) do
      validate_action_has_change(action, AshAuthentication.Strategy.Totp.GenerateSecretChange)
    end
  end

  defp handle_confirm_setup_action(dsl, strategy) when strategy.confirm_setup_enabled? != true,
    do: {:ok, dsl, strategy}

  # sobelow_skip ["DOS.BinToAtom"]
  defp handle_confirm_setup_action(dsl, strategy) when is_nil(strategy.confirm_setup_action_name),
    do:
      handle_confirm_setup_action(dsl, %{
        strategy
        | confirm_setup_action_name: :"confirm_setup_with_#{strategy.name}"
      })

  defp handle_confirm_setup_action(dsl, strategy) do
    with {:ok, dsl} <-
           maybe_build_action(
             dsl,
             strategy.confirm_setup_action_name,
             &build_confirm_setup_action(&1, strategy)
           ),
         :ok <- validate_confirm_setup_action(dsl, strategy) do
      {:ok, dsl, strategy}
    end
  end

  defp build_confirm_setup_action(dsl, strategy) do
    module = Transformer.get_persisted(dsl, :module)

    arguments = [
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :update], :argument,
        name: :setup_token,
        type: :string,
        allow_nil?: false,
        sensitive?: true,
        description: "The setup token from the setup action."
      ),
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :update], :argument,
        name: :code,
        type: :string,
        allow_nil?: false,
        description: "The TOTP code to verify."
      )
    ]

    changes = [
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :update], :change,
        change: AshAuthentication.Strategy.Totp.ConfirmSetupChange,
        description:
          "Verify the TOTP code, revoke the setup token, and store the secret on the user."
      )
    ]

    brute_force_changes =
      case strategy.brute_force_strategy do
        {:audit_log, _audit_log_name} ->
          [
            Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :update], :change,
              change:
                {AshAuthentication.Strategy.Totp.AuditLogChange,
                 action_name: strategy.confirm_setup_action_name}
            )
          ]

        _ ->
          []
      end

    touches_resources =
      case AshAuthentication.Info.authentication_tokens_token_resource(dsl) do
        {:ok, token_resource} -> Enum.uniq([module, token_resource])
        _ -> [module]
      end

    Transformer.build_entity(Ash.Resource.Dsl, [:actions], :update,
      name: strategy.confirm_setup_action_name,
      accept: [],
      arguments: arguments,
      changes: brute_force_changes ++ changes,
      require_atomic?: false,
      touches_resources: touches_resources,
      description: "Confirm TOTP setup by verifying a code and activating the secret."
    )
  end

  defp validate_confirm_setup_action(dsl, strategy) do
    with {:ok, action} <- validate_action_exists(dsl, strategy.confirm_setup_action_name),
         :ok <- validate_action_has_argument(action, :setup_token),
         :ok <-
           validate_action_argument_option(action, :setup_token, :type, [:string, Ash.Type.String]),
         :ok <- validate_action_argument_option(action, :setup_token, :allow_nil?, [false]),
         :ok <- validate_action_has_argument(action, :code),
         :ok <- validate_action_argument_option(action, :code, :type, [:string, Ash.Type.String]),
         :ok <- validate_action_argument_option(action, :code, :allow_nil?, [false]),
         :ok <-
           validate_action_has_change(action, AshAuthentication.Strategy.Totp.ConfirmSetupChange) do
      validate_strategy_change(action, strategy.brute_force_strategy)
    end
  end

  defp handle_sign_in_action(dsl, strategy) when strategy.sign_in_enabled? != true,
    do: {:ok, dsl, strategy}

  # sobelow_skip ["DOS.BinToAtom"]
  defp handle_sign_in_action(dsl, strategy) when is_nil(strategy.sign_in_action_name),
    do:
      handle_sign_in_action(dsl, %{
        strategy
        | sign_in_action_name: :"sign_in_with_#{strategy.name}"
      })

  defp handle_sign_in_action(dsl, strategy) do
    with {:ok, dsl} <-
           maybe_build_action(
             dsl,
             strategy.sign_in_action_name,
             &build_sign_in_action(&1, strategy)
           ),
         :ok <- validate_sign_in_action(dsl, strategy) do
      {:ok, dsl, strategy}
    end
  end

  defp build_sign_in_action(dsl, strategy) do
    identity_attribute = Ash.Resource.Info.attribute(dsl, strategy.identity_field)

    arguments = [
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :read], :argument,
        name: strategy.identity_field,
        type: identity_attribute.type,
        allow_nil?: false,
        description: "The identity to use for retrieving the user."
      ),
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :read], :argument,
        name: :code,
        type: Ash.Type.String,
        allow_nil?: false,
        description: "The TOTP code to check."
      )
    ]

    metadata =
      if AshAuthentication.Info.authentication_tokens_enabled?(dsl) do
        [
          Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :read], :metadata,
            name: :token,
            type: :string,
            allow_nil?: false,
            description: "A JWT which the user can use to authenticate to the API."
          )
        ]
      else
        []
      end

    preparations =
      case strategy.brute_force_strategy do
        {:preparation, preparation} ->
          [
            Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :read], :prepare,
              preparation: preparation
            ),
            Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :read], :prepare,
              preparation: AshAuthentication.Strategy.Totp.SignInPreparation
            )
          ]

        {:audit_log, _audit_log_name} ->
          [
            Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :read], :prepare,
              preparation:
                {AshAuthentication.Strategy.Totp.AuditLogPreparation,
                 action_name: strategy.sign_in_action_name}
            ),
            Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :read], :prepare,
              preparation: AshAuthentication.Strategy.Totp.SignInPreparation
            )
          ]

        _ ->
          [
            Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :read], :prepare,
              preparation: AshAuthentication.Strategy.Totp.SignInPreparation
            )
          ]
      end

    Transformer.build_entity(Ash.Resource.Dsl, [:actions], :read,
      name: strategy.sign_in_action_name,
      arguments: arguments,
      preparations: preparations,
      metadata: metadata,
      get?: true,
      description: "Attempt to sign in using a username and TOTP code."
    )
  end

  defp validate_sign_in_action(dsl, strategy) do
    identity_attribute = Ash.Resource.Info.attribute(dsl, strategy.identity_field)

    with {:ok, action} <- validate_action_exists(dsl, strategy.sign_in_action_name),
         :ok <-
           validate_action_argument_option(action, strategy.identity_field, :type, [
             identity_attribute.type
           ]),
         :ok <- validate_action_has_argument(action, :code),
         :ok <- validate_action_argument_option(action, :code, :type, [:string, Ash.Type.String]),
         :ok <- validate_action_argument_option(action, :code, :allow_nil?, [false]),
         :ok <-
           validate_action_has_preparation(
             action,
             AshAuthentication.Strategy.Totp.SignInPreparation
           ) do
      validate_strategy_preparation(action, strategy.brute_force_strategy)
    end
  end

  defp handle_verify_action(dsl, strategy) when strategy.verify_enabled? != true,
    do: {:ok, dsl, strategy}

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
        description: "The user whose code to check.",
        constraints: [instance_of: module]
      ),
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :action], :argument,
        name: :code,
        type: Ash.Type.String,
        allow_nil?: false,
        description: "The TOTP code to check."
      )
    ]

    touches_resources =
      with {:audit_log, audit_log} <- strategy.brute_force_strategy,
           {:ok, audit_log} <- AshAuthentication.Info.strategy(dsl, audit_log) do
        Enum.uniq([module, audit_log.audit_log_resource])
      else
        _ -> [module]
      end

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

    Transformer.build_entity(Ash.Resource.Dsl, [:actions], :action,
      name: strategy.verify_action_name,
      arguments: arguments,
      returns: Ash.Type.Boolean,
      transaction?: true,
      description: "Is the provided TOTP code valid for the user?",
      touches_resources: touches_resources,
      run: AshAuthentication.Strategy.Totp.VerifyAction,
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
             {AshAuthentication.Strategy.Totp.VerifyAction, []}
           ]),
         :ok <- validate_strategy_preparation(action, strategy.brute_force_strategy) do
      constraints =
        action.arguments
        |> Enum.find(%{}, &(&1.name == :user))
        |> Map.get(:constraints, [])

      if constraints[:instance_of] == module do
        :ok
      else
        module = Transformer.get_persisted(dsl, :module)

        {:error,
         DslError.exception(
           module: module,
           path: [:actions, :action, strategy.verify_action_name, :arguments, :user],
           message: "The argument should have the constraint `[instance_of: #{inspect(module)}]`"
         )}
      end
    end
  end

  defp validate_strategy_preparation(action, {:preparation, preparation}),
    do: validate_action_has_preparation(action, preparation)

  defp validate_strategy_preparation(action, {:audit_log, _audit_log_name}),
    do:
      validate_action_has_preparation(action, AshAuthentication.Strategy.Totp.AuditLogPreparation)

  defp validate_strategy_preparation(_, _), do: :ok

  defp validate_strategy_change(action, {:audit_log, _audit_log_name}),
    do: validate_action_has_change(action, AshAuthentication.Strategy.Totp.AuditLogChange)

  defp validate_strategy_change(_, _), do: :ok

  # sobelow_skip ["DOS.BinToAtom"]
  defp handle_totp_url_calculation(dsl, strategy) when is_nil(strategy.totp_url_field),
    do:
      handle_totp_url_calculation(dsl, %{
        strategy
        | totp_url_field: :"totp_url_for_#{strategy.name}"
      })

  defp handle_totp_url_calculation(dsl, strategy) do
    calculation = Ash.Resource.Info.calculation(dsl, strategy.totp_url_field)

    if calculation do
      with :ok <- validate_totp_url_calculation(dsl, strategy, calculation) do
        {:ok, dsl}
      end
    else
      with {:ok, entity} <-
             Transformer.build_entity(Ash.Resource.Dsl, [:calculations], :calculate,
               sensitive?: true,
               name: strategy.totp_url_field,
               type: :string,
               calculation:
                 {AshAuthentication.Strategy.Totp.TotpUrlCalculation,
                  strategy_name: strategy.name}
             ) do
        {:ok, Transformer.add_entity(dsl, [:calculations], entity)}
      end
    end
  end

  defp validate_totp_url_calculation(dsl, strategy, calculation) do
    with :ok <- validate_calculation_sensitivity(dsl, calculation, true),
         :ok <- validate_calculation_type(dsl, calculation, [:string, Ash.Type.String]) do
      validate_calculation_calculation(
        dsl,
        calculation,
        {AshAuthentication.Strategy.Totp, strategy_name: strategy.name}
      )
    end
  end

  defp validate_calculation_sensitivity(_dsl, %{sensitive?: value}, value), do: :ok

  defp validate_calculation_sensitivity(dsl, calculation, _expected_sensitive) do
    module = Transformer.get_persisted(dsl, :module)

    {:error,
     DslError.exception(
       module: module,
       path: [:calculations, :calculate, calculation.name],
       message: """
       This calculation should be marked as sensitive.
       """
     )}
  end

  defp validate_calculation_type(dsl, calculation, types) do
    with {:error, message} <- validate_field_in_values(calculation, :type, types) do
      {:error,
       DslError.exception(
         module: Transformer.get_persisted(dsl, :module),
         path: [:calculations, :calculate, calculation.name],
         message: message
       )}
    end
  end

  defp validate_calculation_calculation(dsl, calculation, value) do
    with {:error, message} <- validate_field_in_values(calculation, :calculation, [value]) do
      {:error,
       DslError.exception(
         module: Transformer.get_persisted(dsl, :module),
         path: [:calculations, :calculate, calculation.name],
         message: message
       )}
    end
  end

  defp validate_last_totp_at_field(field, dsl) do
    with {:ok, resource} <- persisted_option(dsl, :module),
         {:ok, attribute} <- find_attribute(dsl, field),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :public?, [false]),
         :ok <-
           validate_attribute_option(attribute, resource, :type, [:datetime, Ash.Type.DateTime]) do
      validate_attribute_option(attribute, resource, :sensitive?, [true])
    end
  end
end
