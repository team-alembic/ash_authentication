defmodule AshAuthentication.Strategy.Password.Transformer do
  @moduledoc """
  DSL transformer for the password strategy.

  Iterates through any password authentication strategies and ensures that all
  the correct actions and settings are in place.
  """

  alias Ash.{Resource, Type}
  alias AshAuthentication.{GenerateTokenChange, Strategy, Strategy.Password}
  alias Spark.{Dsl.Transformer, Error.DslError}
  import AshAuthentication.Strategy.Custom.Helpers
  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action
  import AshAuthentication.Validations.Attribute

  @doc false
  @spec transform(Password.t(), map) :: {:ok, Password.t() | map} | {:error, Exception.t()}
  def transform(strategy, dsl_state) do
    with :ok <- validate_identity_field(strategy.identity_field, dsl_state),
         :ok <- validate_hashed_password_field(strategy.hashed_password_field, dsl_state),
         strategy <-
           maybe_set_field_lazy(strategy, :register_action_name, &:"register_with_#{&1.name}"),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             strategy.register_action_name,
             &build_register_action(&1, strategy)
           ),
         :ok <- validate_register_action(dsl_state, strategy),
         strategy <-
           maybe_set_field_lazy(strategy, :sign_in_action_name, &:"sign_in_with_#{&1.name}"),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             strategy.sign_in_action_name,
             &build_sign_in_action(&1, strategy)
           ),
         :ok <- validate_sign_in_action(dsl_state, strategy),
         {:ok, dsl_state, strategy} <- maybe_transform_resettable(dsl_state, strategy),
         {:ok, resource} <- persisted_option(dsl_state, :module) do
      strategy = %{strategy | resource: resource}

      dsl_state =
        dsl_state
        |> Transformer.replace_entity(
          ~w[authentication strategies]a,
          strategy,
          &(Strategy.name(&1) == strategy.name)
        )
        |> then(fn dsl_state ->
          ~w[sign_in_action_name register_action_name]a
          |> Enum.map(&Map.get(strategy, &1))
          |> register_strategy_actions(dsl_state, strategy)
        end)
        |> then(fn dsl_state ->
          strategy
          |> Map.get(:resettable, [])
          |> Enum.flat_map(fn resettable ->
            ~w[request_password_reset_action_name password_reset_action_name]a
            |> Enum.map(&Map.get(resettable, &1))
          end)
          |> register_strategy_actions(dsl_state, strategy)
        end)

      {:ok, dsl_state}
    end
  end

  defp validate_identity_field(identity_field, dsl_state) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, identity_field),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]) do
      validate_attribute_unique_constraint(dsl_state, [identity_field], resource)
    end
  end

  defp validate_hashed_password_field(hashed_password_field, dsl_state) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, hashed_password_field),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]) do
      validate_attribute_option(attribute, resource, :sensitive?, [true])
    end
  end

  defp build_register_action(dsl_state, strategy) do
    password_opts = [
      type: Type.String,
      allow_nil?: false,
      constraints: [min_length: 8],
      sensitive?: true
    ]

    arguments =
      [
        Transformer.build_entity!(
          Resource.Dsl,
          [:actions, :create],
          :argument,
          Keyword.put(password_opts, :name, strategy.password_field)
        )
      ]
      |> maybe_append(
        strategy.confirmation_required?,
        Transformer.build_entity!(
          Resource.Dsl,
          [:actions, :create],
          :argument,
          Keyword.put(password_opts, :name, strategy.password_confirmation_field)
        )
      )

    changes =
      []
      |> maybe_append(
        strategy.confirmation_required?,
        Transformer.build_entity!(Resource.Dsl, [:actions, :create], :validate,
          validation: Password.PasswordConfirmationValidation
        )
      )
      |> Enum.concat([
        Transformer.build_entity!(Resource.Dsl, [:actions, :create], :change,
          change: Password.HashPasswordChange
        ),
        Transformer.build_entity!(Resource.Dsl, [:actions, :create], :change,
          change: GenerateTokenChange
        )
      ])

    metadata =
      if AshAuthentication.Info.authentication_tokens_enabled?(dsl_state) do
        [
          Transformer.build_entity!(Resource.Dsl, [:actions, :create], :metadata,
            name: :token,
            type: :string,
            allow_nil?: false
          )
        ]
      else
        []
      end

    Transformer.build_entity(Resource.Dsl, [:actions], :create,
      name: strategy.register_action_name,
      arguments: arguments,
      changes: changes,
      metadata: metadata,
      allow_nil_input: [strategy.hashed_password_field]
    )
  end

  defp validate_register_action(dsl_state, strategy) do
    with {:ok, action} <- validate_action_exists(dsl_state, strategy.register_action_name),
         :ok <- validate_password_argument(action, strategy.password_field, true),
         :ok <-
           validate_password_argument(
             action,
             strategy.password_confirmation_field,
             strategy.confirmation_required?
           ),
         :ok <- validate_action_has_change(action, Password.HashPasswordChange),
         :ok <- validate_action_has_change(action, GenerateTokenChange) do
      validate_action_has_validation(
        action,
        Password.PasswordConfirmationValidation,
        strategy.confirmation_required?
      )
    end
  end

  defp validate_password_argument(action, field, true) do
    with :ok <- validate_action_argument_option(action, field, :type, [Ash.Type.String]) do
      validate_action_argument_option(action, field, :sensitive?, [true])
    end
  end

  defp validate_password_argument(_action, _field, _), do: :ok

  defp validate_action_has_validation(action, validation, true),
    do: validate_action_has_validation(action, validation)

  defp validate_action_has_validation(_action, _validation, _), do: :ok

  defp build_sign_in_action(dsl_state, strategy) do
    identity_attribute = Resource.Info.attribute(dsl_state, strategy.identity_field)

    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: strategy.identity_field,
        type: identity_attribute.type,
        allow_nil?: false
      ),
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: strategy.password_field,
        type: Type.String,
        allow_nil?: false,
        sensitive?: true
      )
    ]

    preparations = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
        preparation: Password.SignInPreparation
      )
    ]

    metadata =
      if AshAuthentication.Info.authentication_tokens_enabled?(dsl_state) do
        [
          Transformer.build_entity!(Resource.Dsl, [:actions, :read], :metadata,
            name: :token,
            type: :string,
            allow_nil?: false
          )
        ]
      else
        []
      end

    Transformer.build_entity(Resource.Dsl, [:actions], :read,
      name: strategy.sign_in_action_name,
      arguments: arguments,
      preparations: preparations,
      metadata: metadata,
      get?: true
    )
  end

  defp validate_sign_in_action(dsl_state, strategy) do
    with {:ok, action} <- validate_action_exists(dsl_state, strategy.sign_in_action_name),
         :ok <- validate_identity_argument(dsl_state, action, strategy.identity_field),
         :ok <- validate_password_argument(action, strategy.password_field, true) do
      validate_action_has_preparation(action, Password.SignInPreparation)
    end
  end

  defp validate_identity_argument(dsl_state, action, identity_field) do
    identity_attribute = Ash.Resource.Info.attribute(dsl_state, identity_field)
    validate_action_argument_option(action, identity_field, :type, [identity_attribute.type])
  end

  defp maybe_transform_resettable(dsl_state, %{resettable: []} = strategy),
    do: {:ok, dsl_state, strategy}

  defp maybe_transform_resettable(dsl_state, %{resettable: [resettable]} = strategy) do
    with resettable <-
           maybe_set_field_lazy(
             resettable,
             :request_password_reset_action_name,
             fn _ -> :"request_password_reset_with_#{strategy.name}" end
           ),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             resettable.request_password_reset_action_name,
             &build_reset_request_action(&1, resettable, strategy)
           ),
         :ok <- validate_reset_request_action(dsl_state, resettable, strategy),
         resettable <-
           maybe_set_field_lazy(
             resettable,
             :password_reset_action_name,
             fn _ -> :"password_reset_with_#{strategy.name}" end
           ),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             resettable.password_reset_action_name,
             &build_reset_action(&1, resettable, strategy)
           ),
         :ok <- validate_reset_action(dsl_state, resettable, strategy) do
      {:ok, dsl_state, %{strategy | resettable: [resettable]}}
    else
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp maybe_transform_resettable(_dsl_state, %{resettable: [_ | _]}),
    do:
      DslError.exception(
        path: [:authentication, :strategies, :password],
        message: "Only one `resettable` entity may be present."
      )

  defp build_reset_request_action(dsl_state, resettable, strategy) do
    identity_attribute = Resource.Info.attribute(dsl_state, strategy.identity_field)

    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: strategy.identity_field,
        type: identity_attribute.type,
        allow_nil?: false
      )
    ]

    preparations = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
        preparation: Password.RequestPasswordResetPreparation
      )
    ]

    Transformer.build_entity(Resource.Dsl, [:actions], :read,
      name: resettable.request_password_reset_action_name,
      arguments: arguments,
      preparations: preparations
    )
  end

  defp validate_reset_request_action(dsl_state, resettable, strategy) do
    with {:ok, action} <-
           validate_action_exists(dsl_state, resettable.request_password_reset_action_name),
         :ok <- validate_identity_argument(dsl_state, action, strategy.identity_field) do
      validate_action_has_preparation(action, Password.RequestPasswordResetPreparation)
    end
  end

  defp build_reset_action(_dsl_state, resettable, strategy) do
    password_opts = [
      type: Type.String,
      allow_nil?: false,
      constraints: [min_length: 8],
      sensitive?: true
    ]

    arguments =
      [
        Transformer.build_entity!(
          Resource.Dsl,
          [:actions, :update],
          :argument,
          name: :reset_token,
          type: Type.String,
          sensitive?: true
        ),
        Transformer.build_entity!(
          Resource.Dsl,
          [:actions, :update],
          :argument,
          Keyword.put(password_opts, :name, strategy.password_field)
        )
      ]
      |> maybe_append(
        strategy.confirmation_required?,
        Transformer.build_entity!(
          Resource.Dsl,
          [:actions, :update],
          :argument,
          Keyword.put(password_opts, :name, strategy.password_confirmation_field)
        )
      )

    changes =
      [
        Transformer.build_entity!(Resource.Dsl, [:actions, :update], :validate,
          validation: Password.ResetTokenValidation
        )
      ]
      |> maybe_append(
        strategy.confirmation_required?,
        Transformer.build_entity!(Resource.Dsl, [:actions, :update], :validate,
          validation: Password.PasswordConfirmationValidation
        )
      )
      |> Enum.concat([
        Transformer.build_entity!(Resource.Dsl, [:actions, :update], :change,
          change: Password.HashPasswordChange
        ),
        Transformer.build_entity!(Resource.Dsl, [:actions, :update], :change,
          change: GenerateTokenChange
        )
      ])

    metadata = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :update], :metadata,
        name: :token,
        type: :string,
        allow_nil?: false
      )
    ]

    Transformer.build_entity(Resource.Dsl, [:actions], :update,
      name: resettable.password_reset_action_name,
      arguments: arguments,
      changes: changes,
      metadata: metadata,
      accept: []
    )
  end

  defp validate_reset_action(dsl_state, resettable, strategy) do
    with {:ok, action} <-
           validate_action_exists(dsl_state, resettable.password_reset_action_name),
         :ok <- validate_action_has_validation(action, Password.ResetTokenValidation),
         :ok <- validate_action_has_change(action, Password.HashPasswordChange),
         :ok <- validate_password_argument(action, strategy.password_field, true),
         :ok <-
           validate_password_argument(
             action,
             strategy.password_confirmation_field,
             strategy.confirmation_required?
           ),
         :ok <-
           validate_action_has_validation(
             action,
             Password.PasswordConfirmationValidation,
             strategy.confirmation_required?
           ) do
      validate_action_has_change(action, GenerateTokenChange)
    end
  end
end
