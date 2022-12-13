defmodule AshAuthentication.Strategy.Password.Transformer do
  @moduledoc """
  DSL transformer for the password strategy.

  Iterates through any password authentication strategies and ensures that all
  the correct actions and settings are in place.
  """

  use Spark.Dsl.Transformer

  alias Ash.{Resource, Type}
  alias AshAuthentication.{GenerateTokenChange, Info, Strategy.Password}
  alias Spark.{Dsl.Transformer, Error.DslError}
  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action
  import AshAuthentication.Validations.Attribute

  @doc false
  @impl true
  @spec after?(module) :: boolean
  def after?(AshAuthentication.Transformer), do: true
  def after?(_), do: false

  @doc false
  @impl true
  @spec before?(module) :: boolean
  def before?(Resource.Transformers.DefaultAccept), do: true
  def before?(_), do: false

  @doc false
  @impl true
  @spec transform(map) ::
          :ok
          | {:ok, map()}
          | {:error, term()}
          | {:warn, map(), String.t() | [String.t()]}
          | :halt
  def transform(dsl_state) do
    dsl_state
    |> Info.authentication_strategies()
    |> Stream.filter(&is_struct(&1, Password))
    |> Enum.reduce_while({:ok, dsl_state}, fn strategy, {:ok, dsl_state} ->
      case transform_strategy(strategy, dsl_state) do
        {:ok, dsl_state} -> {:cont, {:ok, dsl_state}}
        {:error, reason} -> {:halt, {:error, reason}}
      end
    end)
  end

  defp transform_strategy(strategy, dsl_state) do
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
          &(&1.name == strategy.name)
        )
        |> then(fn dsl_state ->
          ~w[sign_in_action_name register_action_name]a
          |> Stream.map(&Map.get(strategy, &1))
          |> Enum.reduce(
            dsl_state,
            &Transformer.persist(&2, {:authentication_action, &1}, strategy)
          )
        end)
        |> then(fn dsl_state ->
          strategy
          |> Map.get(:resettable, [])
          |> Stream.flat_map(fn resettable ->
            ~w[request_password_reset_action_name password_reset_action_name]a
            |> Stream.map(&Map.get(resettable, &1))
          end)
          |> Enum.reduce(
            dsl_state,
            &Transformer.persist(&2, {:authentication_action, &1}, strategy)
          )
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

  defp build_register_action(_dsl_state, strategy) do
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

    Transformer.build_entity(Resource.Dsl, [:actions], :create,
      name: strategy.register_action_name,
      arguments: arguments,
      changes: changes,
      allow_nil_input: [strategy.hashed_password_field]
    )
  end

  defp validate_register_action(dsl_state, strategy) do
    with {:ok, action} <- validate_action_exists(dsl_state, strategy.register_action_name),
         :ok <- validate_allow_nil_input(action, strategy.hashed_password_field),
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

  defp validate_allow_nil_input(action, field) do
    allowed_nil_fields = Map.get(action, :allow_nil_input, [])

    if field in allowed_nil_fields do
      :ok
    else
      {:error,
       DslError.exception(
         path: [:actions, :allow_nil_input],
         message:
           "Expected the action `#{inspect(action.name)}` to allow nil input for the field `#{inspect(field)}`"
       )}
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

    Transformer.build_entity(Resource.Dsl, [:actions], :read,
      name: strategy.sign_in_action_name,
      arguments: arguments,
      preparations: preparations,
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

    Transformer.build_entity(Resource.Dsl, [:actions], :update,
      name: resettable.password_reset_action_name,
      arguments: arguments,
      changes: changes,
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
