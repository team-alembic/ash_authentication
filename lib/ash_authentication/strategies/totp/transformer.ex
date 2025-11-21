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

  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action
  import AshAuthentication.Validations.Attribute

  @doc false
  @spec transform(Totp.t(), map) :: {:ok, Totp.t() | map} | {:error, Exception.t()}
  def transform(strategy, dsl) do
    with strategy <- maybe_set_field_lazy(strategy, :issuer, &to_string(&1.name)),
         :ok <- validate_identity_field(strategy.identity_field, dsl),
         :ok <- validate_secret_field(strategy.secret_field, dsl),
         :ok <- validate_last_totp_at_field(strategy.last_totp_at_field, dsl),
         {:ok, dsl, strategy} <- handle_setup_action(dsl, strategy),
         {:ok, dsl, strategy} <- handle_sign_in_action(dsl, strategy),
         {:ok, dsl, strategy} <- handle_verify_action(dsl, strategy),
         {:ok, dsl, strategy} <- handle_totp_url_calculation(dsl, strategy),
         {:ok, resource} <- persisted_option(dsl, :module) do
      strategy = %{strategy | resource: resource}

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

  defp handle_setup_action(dsl, strategy) when strategy.setup_enabled? != true,
    do: {:ok, dsl, strategy}

  defp handle_setup_action(dsl, strategy) when is_nil(strategy.setup_action_name),
    do: handle_setup_action(dsl, %{strategy | setup_action_name: :"setup_with_#{strategy.name}"})

  defp handle_setup_action(dsl, strategy) do
    with {:ok, dsl} <-
           maybe_build_action(dsl, strategy.setup_action_name, &build_setup_action(&1, strategy)),
         :ok <- validate_setup_action(dsl, strategy) do
      {:ok, dsl, strategy}
    end
  end

  defp build_setup_action(_dsl, strategy) do
    changes =
      [
        Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :update], :change,
          change: AshAuthentication.Strategy.Totp.GenerateSecretChange,
          description:
            "Generate a new TOTP secret and store it in the `#{inspect(strategy.secret_field)}` attribute."
        )
      ]

    arguments = [
      Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :update], :argument,
        name: :force?,
        type: Ash.Type.Boolean,
        allow_nil?: false,
        default: false,
        description: "Replace an existing TOTP secret if one is already present."
      )
    ]

    Transformer.build_entity(Ash.Resource.Dsl, [:actions], :update,
      name: strategy.setup_action_name,
      accept: [],
      changes: changes,
      arguments: arguments,
      description:
        "Generate a new TOTP secret and store it in the `#{inspect(strategy.secret_field)}` attribute."
    )
  end

  defp validate_setup_action(dsl, strategy) do
    with {:ok, action} <- validate_action_exists(dsl, strategy.setup_action_name) do
      validate_action_has_change(action, AshAuthentication.Strategy.Totp.GenerateSecretChange)
    end
  end

  defp handle_sign_in_action(dsl, strategy) when strategy.sign_in_enabled? != true,
    do: {:ok, dsl, strategy}

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
          Transformer.build_entity!(Resource.Dsl, [:actions, :read], :metadata,
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

  defp validate_strategy_preparation(_, _), do: :ok

  defp handle_totp_url_calculation(dsl, strategy) when is_nil(strategy.totp_url_field),
    do:
      handle_totp_url_calculation(dsl, %{
        strategy
        | totp_url_field: :"totp_url_for_#{strategy.name}"
      })

  defp handle_totp_url_calculation(dsl, strategy) do
    calculation = Ash.Resource.Info.calculation(dsl, strategy.totp_url_field)

    if calculation do
      with :ok <- validate_totp_url_calculation(dsl, strategy) do
        {:ok, dsl, strategy}
      end
    else
      with {:ok, dsl} <- build_totp_url_calculation(dsl, strategy),
           :ok <- validate_totp_url_calculation(dsl, strategy) do
        {:ok, dsl, strategy}
      end
    end
  end

  defp build_totp_url_calculation(dsl, strategy) do
    {:ok, dsl}
  end

  defp validate_totp_url_calculation(dsl, strategy) do
    :ok
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
