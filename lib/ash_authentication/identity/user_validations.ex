defmodule AshAuthentication.Identity.UserValidations do
  @moduledoc """
  Provides validations for the "user" resource.
  """
  alias Ash.Resource.Actions
  alias AshAuthentication.HashProvider

  alias AshAuthentication.Identity.{
    GenerateTokenChange,
    HashPasswordChange,
    Info,
    PasswordConfirmationValidation,
    SignInPreparation
  }

  alias Spark.{Dsl, Dsl.Transformer, Error.DslError}
  import AshAuthentication.Validations.Action
  import AshAuthentication.Validations.Attribute

  def validate_authentication_extension(dsl_state) do
    extensions = Transformer.get_persisted(dsl_state, :extensions, [])

    if AshAuthentication in extensions,
      do: :ok,
      else:
        {:error,
         DslError.exception(
           path: [:extensions],
           message:
             "The `AshAuthentication` extension must also be present on this resource for identity to work."
         )}
  end

  @doc "Validate that the configured hash provider implements the `HashProvider` behaviour"
  @spec validate_hash_provider(Dsl.t()) :: :ok | {:error, Exception.t()}
  def validate_hash_provider(dsl_state) do
    case Info.hash_provider(dsl_state) do
      {:ok, hash_provider} ->
        validate_module_implements_behaviour(hash_provider, HashProvider)

      :error ->
        {:error,
         DslError.exception(
           path: [:identity_authentication, :hash_provider],
           message: "A hash provider must be set in your identity resource"
         )}
    end
  end

  @doc "Validates information about the sign in action"
  @spec validate_sign_in_action(Dsl.t()) :: {:ok, Dsl.t()} | {:error, Exception.t()}
  def validate_sign_in_action(dsl_state) do
    with {:ok, identity_field} <- Info.identity_field(dsl_state),
         {:ok, password_field} <- Info.password_field(dsl_state),
         {:ok, action} <- validate_action_exists(dsl_state, :sign_in),
         :ok <- validate_identity_argument(action, identity_field),
         :ok <- validate_password_argument(action, password_field),
         :ok <- validate_action_has_preparation(action, SignInPreparation) do
      {:ok, dsl_state}
    end
  end

  @doc "Validates information about the register action"
  @spec validate_register_action(Dsl.t()) :: {:ok, Dsl.t()} | {:error, Exception.t()}
  def validate_register_action(dsl_state) do
    with {:ok, password_field} <- Info.password_field(dsl_state),
         {:ok, password_confirmation_field} <- Info.password_confirmation_field(dsl_state),
         {:ok, confirmation_required?} <- Info.confirmation_required?(dsl_state),
         {:ok, action} <- validate_action_exists(dsl_state, :register),
         :ok <- validate_password_argument(action, password_field),
         :ok <-
           validate_password_confirmation_argument(
             action,
             password_confirmation_field,
             confirmation_required?
           ),
         :ok <- validate_action_has_change(action, HashPasswordChange),
         :ok <- validate_action_has_change(action, GenerateTokenChange),
         :ok <-
           validate_action_has_validation(
             action,
             PasswordConfirmationValidation,
             confirmation_required?
           ) do
      {:ok, dsl_state}
    end
  end

  @doc "Optionally validates that the action has a validation"
  @spec validate_action_has_validation(Actions.action(), module, really? :: boolean) ::
          :ok | {:error, Exception.t()}
  def validate_action_has_validation(_, _, false), do: :ok

  def validate_action_has_validation(action, validation, _),
    do: validate_action_has_validation(action, validation)

  @doc "Validate the identity argument"
  @spec validate_identity_argument(Actions.action(), atom) :: :ok | {:error, Exception.t()}
  def validate_identity_argument(action, identity_field) do
    validate_action_argument_option(action, identity_field, :type, [Ash.Type.String])
  end

  @doc "Validate the password argument"
  @spec validate_password_argument(Actions.action(), atom) :: :ok | {:error, Exception.t()}
  def validate_password_argument(action, password_field) do
    with :ok <- validate_action_argument_option(action, password_field, :type, [Ash.Type.String]) do
      validate_action_argument_option(action, password_field, :sensitive?, [true])
    end
  end

  @doc "Optionally validates the password confirmation argument"
  @spec validate_password_confirmation_argument(Actions.action(), atom, really? :: boolean) ::
          :ok | {:error, Exception.t()}
  def validate_password_confirmation_argument(_, _, false), do: :ok

  def validate_password_confirmation_argument(action, confirm_field, _),
    do: validate_password_argument(action, confirm_field)

  @doc "Validate the identity field in the user resource"
  @spec validate_identity_field(Dsl.t()) :: {:ok, Dsl.t()} | {:error, Exception.t()}
  def validate_identity_field(dsl_state) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, identity_field} <- Info.identity_field(dsl_state),
         {:ok, attribute} <- find_attribute(dsl_state, identity_field),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]),
         :ok <- validate_attribute_unique_constraint(dsl_state, identity_field, resource) do
      {:ok, dsl_state}
    end
  end

  @spec validate_hashed_password_field(Dsl.t()) :: {:ok, Dsl.t()} | {:error, Exception.t()}
  def validate_hashed_password_field(dsl_state) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, hashed_password_field} <- identity_option(dsl_state, :hashed_password_field),
         {:ok, attribute} <- find_attribute(dsl_state, hashed_password_field),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]),
         :ok <- validate_attribute_option(attribute, resource, :sensitive?, [true]) do
      {:ok, dsl_state}
    end
  end

  defp identity_option(dsl_state, option) do
    case Transformer.get_option(dsl_state, [:identity_authentication], option) do
      nil -> {:error, {:unknown_option, option}}
      value -> {:ok, value}
    end
  end

  def persisted_option(dsl_state, option) do
    case Transformer.get_persisted(dsl_state, option) do
      nil -> {:error, {:unknown_persisted, option}}
      value -> {:ok, value}
    end
  end

  defp find_attribute(dsl_state, attribute_name) do
    dsl_state
    |> Transformer.get_entities([:attributes])
    |> Enum.find(&(&1.name == attribute_name))
    |> case do
      nil ->
        resource = Transformer.get_persisted(dsl_state, :module)

        {:error,
         DslError.exception(
           path: [:attributes, :attribute],
           message:
             "The resource `#{inspect(resource)}` does not define an attribute named `#{inspect(attribute_name)}`"
         )}

      attribute ->
        {:ok, attribute}
    end
  end

  defp validate_module_implements_behaviour(module, behaviour) do
    behaviours =
      :attributes
      |> module.__info__()
      |> Keyword.get(:behaviour, [])

    if behaviour in behaviours,
      do: :ok,
      else:
        {:error,
         "Expected `#{inspect(module)}` to implement the `#{inspect(behaviour)}` behaviour"}
  rescue
    _ ->
      {:error, "Expected `#{inspect(module)}` to implement the `#{inspect(behaviour)}` behaviour"}
  end
end
