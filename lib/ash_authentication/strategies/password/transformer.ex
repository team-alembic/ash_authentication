defmodule AshAuthentication.Strategy.Password.Transformer do
  @moduledoc """
  DSL transformer for the password strategy.

  Iterates through any password authentication strategies and ensures that all
  the correct actions and settings are in place.
  """

  alias Ash.{Resource, Type}
  alias AshAuthentication.{GenerateTokenChange, Strategy, Strategy.Password}
  alias Spark.Dsl.Transformer
  import AshAuthentication.Strategy.Custom.Helpers
  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action
  import AshAuthentication.Validations.Attribute

  @doc false
  @spec transform(Password.t(), map) :: {:ok, Password.t() | map} | {:error, Exception.t()}
  # sobelow_skip ["DOS.BinToAtom"]
  def transform(strategy, dsl_state) do
    with :ok <- validate_identity_field(strategy.identity_field, dsl_state),
         :ok <- validate_hashed_password_field(strategy.hashed_password_field, dsl_state),
         strategy <- maybe_transform_token_lifetime(strategy, :sign_in_token_lifetime, :seconds),
         strategy <-
           maybe_set_field_lazy(strategy, :register_action_name, &:"register_with_#{&1.name}"),
         {:ok, dsl_state} <-
           maybe_maybe_build_action(
             strategy.registration_enabled?,
             dsl_state,
             strategy.register_action_name,
             &build_register_action(&1, strategy)
           ),
         :ok <- validate_register_action(dsl_state, strategy),
         strategy <-
           maybe_set_field_lazy(strategy, :sign_in_action_name, &:"sign_in_with_#{&1.name}"),
         {:ok, dsl_state} <-
           maybe_maybe_build_action(
             strategy.sign_in_enabled?,
             dsl_state,
             strategy.sign_in_action_name,
             &build_sign_in_action(&1, strategy)
           ),
         :ok <- validate_sign_in_action(dsl_state, strategy),
         strategy <-
           maybe_set_field_lazy(
             strategy,
             :sign_in_with_token_action_name,
             &:"sign_in_with_token_for_#{&1.name}"
           ),
         {:ok, dsl_state} <-
           maybe_maybe_build_action(
             strategy.sign_in_tokens_enabled?,
             dsl_state,
             strategy.sign_in_with_token_action_name,
             &build_sign_in_with_token_action(&1, strategy)
           ),
         :ok <- validate_sign_in_with_token_action(dsl_state, strategy),
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
          ~w[sign_in_action_name register_action_name sign_in_with_token_action_name]a
          |> Enum.map(&Map.get(strategy, &1))
          |> register_strategy_actions(dsl_state, strategy)
        end)
        |> then(fn dsl_state ->
          strategy
          |> Map.get(:resettable, %{})
          |> Kernel.||(%{})
          |> Map.take(~w[request_password_reset_action_name password_reset_action_name]a)
          |> Map.values()
          |> register_strategy_actions(dsl_state, strategy)
        end)

      {:ok, dsl_state}
    end
  end

  defp maybe_transform_token_lifetime(strategy, field, default_unit) do
    case Map.get(strategy, field) do
      ttl when is_integer(ttl) -> Map.put(strategy, field, {ttl, default_unit})
      _ -> strategy
    end
  end

  defp validate_identity_field(identity_field, dsl_state) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, identity_field),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]),
         :ok <- validate_attribute_option(attribute, resource, :public?, [true]) do
      validate_attribute_unique_constraint(dsl_state, [identity_field], resource)
    end
  end

  defp validate_hashed_password_field(hashed_password_field, dsl_state) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, hashed_password_field),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :sensitive?, [true]) do
      validate_attribute_option(attribute, resource, :public?, [false])
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
          password_opts
          |> Keyword.put(:name, strategy.password_field)
          |> Keyword.put(:description, "The proposed password for the user, in plain text.")
        )
      ]
      |> maybe_append(
        strategy.confirmation_required?,
        Transformer.build_entity!(
          Resource.Dsl,
          [:actions, :create],
          :argument,
          password_opts
          |> Keyword.put(:name, strategy.password_confirmation_field)
          |> Keyword.put(
            :description,
            "The proposed password for the user (again), in plain text."
          )
        )
      )

    changes =
      []
      |> maybe_append(
        strategy.confirmation_required?,
        Transformer.build_entity!(Resource.Dsl, [:actions, :create], :validate,
          validation: Password.PasswordConfirmationValidation,
          description:
            "Confirm that the values of `#{inspect(strategy.password_field)}` and `#{inspect(strategy.password_confirmation_field)}` are the same if confirmation is enabled."
        )
      )
      |> Enum.concat([
        Transformer.build_entity!(Resource.Dsl, [:actions, :create], :change,
          change: Password.HashPasswordChange,
          description:
            "Generate a cryptographic hash of the user's plain text password and store it in the `#{inspect(strategy.hashed_password_field)}` attribute."
        ),
        Transformer.build_entity!(Resource.Dsl, [:actions, :create], :change,
          change: GenerateTokenChange,
          description:
            "If token generation is enabled, generate a token and store it in the user's metadata."
        )
      ])

    metadata =
      if AshAuthentication.Info.authentication_tokens_enabled?(dsl_state) do
        [
          Transformer.build_entity!(Resource.Dsl, [:actions, :create], :metadata,
            name: :token,
            type: :string,
            allow_nil?: false,
            description: "A JWT which the user can use to authenticate to the API."
          )
        ]
      else
        []
      end

    accept =
      [strategy.identity_field]
      |> Enum.concat(List.wrap(strategy.register_action_accept))
      |> Enum.uniq()

    Transformer.build_entity(Resource.Dsl, [:actions], :create,
      name: strategy.register_action_name,
      accept: accept,
      arguments: arguments,
      changes: changes,
      metadata: metadata,
      allow_nil_input: [strategy.hashed_password_field],
      description: "Register a new user with a username and password."
    )
  end

  defp validate_register_action(dsl_state, strategy)
       when strategy.registration_enabled? == true do
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

  defp validate_register_action(_dsl_state, _strategy), do: :ok

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
        allow_nil?: false,
        description: "The identity to use for retrieving the user."
      ),
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: strategy.password_field,
        type: Type.String,
        allow_nil?: false,
        sensitive?: true,
        description: "The password to check for the matching user."
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
            allow_nil?: false,
            description: "A JWT which the user can use to authenticate to the API."
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
      get?: true,
      description: "Attempt to sign in using a username and password."
    )
  end

  defp validate_sign_in_action(dsl_state, strategy) when strategy.sign_in_enabled? == true do
    with {:ok, action} <- validate_action_exists(dsl_state, strategy.sign_in_action_name),
         :ok <- validate_identity_argument(dsl_state, action, strategy.identity_field),
         :ok <- validate_password_argument(action, strategy.password_field, true) do
      validate_action_has_preparation(action, Password.SignInPreparation)
    end
  end

  defp validate_sign_in_action(_dsl_state, _strategy), do: :ok

  defp validate_identity_argument(dsl_state, action, identity_field) do
    identity_attribute = Ash.Resource.Info.attribute(dsl_state, identity_field)
    validate_action_argument_option(action, identity_field, :type, [identity_attribute.type])
  end

  defp build_sign_in_with_token_action(_dsl_state, strategy) do
    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: :token,
        type: :string,
        allow_nil?: false,
        sensitive?: true,
        description: "The short-lived sign in JWT."
      )
    ]

    preparations = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
        preparation: Password.SignInWithTokenPreparation
      )
    ]

    metadata = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :metadata,
        name: :token,
        type: :string,
        allow_nil?: false,
        description: "A JWT which the user can use to authenticate to the API."
      )
    ]

    Transformer.build_entity(Resource.Dsl, [:actions], :read,
      name: strategy.sign_in_with_token_action_name,
      arguments: arguments,
      preparations: preparations,
      metadata: metadata,
      get?: true,
      description: "Attempt to sign in using a short-lived sign in token."
    )
  end

  defp validate_sign_in_with_token_action(dsl_state, strategy)
       when strategy.sign_in_tokens_enabled? == true do
    with {:ok, action} <-
           validate_action_exists(dsl_state, strategy.sign_in_with_token_action_name),
         :ok <- validate_token_argument(action) do
      validate_action_has_preparation(action, Password.SignInWithTokenPreparation)
    end
  end

  defp validate_sign_in_with_token_action(_dsl_state, _strategy), do: :ok

  defp validate_token_argument(action) do
    with :ok <-
           validate_action_argument_option(action, :token, :type, [Ash.Type.String, :string]),
         :ok <- validate_action_argument_option(action, :token, :allow_nil?, [false]) do
      validate_action_argument_option(action, :token, :sensitive?, [true])
    end
  end

  defp maybe_maybe_build_action(true, dsl_state, action_name, builder),
    do: maybe_build_action(dsl_state, action_name, builder)

  defp maybe_maybe_build_action(false, dsl_state, _action_name, _builder), do: {:ok, dsl_state}

  defp maybe_transform_resettable(dsl_state, %{resettable: nil} = strategy),
    do: {:ok, dsl_state, strategy}

  # sobelow_skip ["DOS.BinToAtom"]
  defp maybe_transform_resettable(dsl_state, %{resettable: resettable} = strategy) do
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
         resettable <- maybe_transform_token_lifetime(resettable, :token_lifetime, :hours),
         :ok <-
           validate_reset_action(dsl_state, resettable, strategy) do
      {:ok, dsl_state, %{strategy | resettable: resettable}}
    else
      {:error, reason} ->
        {:error, reason}
    end
  end

  defp build_reset_request_action(dsl_state, resettable, strategy) do
    identity_attribute = Resource.Info.attribute(dsl_state, strategy.identity_field)

    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: strategy.identity_field,
        type: identity_attribute.type,
        allow_nil?: false,
        description: "The proposed identity to send reset instructions to."
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
      preparations: preparations,
      description: "Send password reset instructions to a user if they exist."
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
      accept: [],
      require_atomic?: false
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
