defmodule AshAuthentication.PasswordReset.Transformer do
  @moduledoc """
  The PasswordReset transformer.

  Scans the resource and checks that all the fields and actions needed are
  present.
  """

  use Spark.Dsl.Transformer

  alias AshAuthentication.PasswordReset.{
    Info,
    RequestPasswordResetPreparation,
    ResetTokenValidation
  }

  alias Ash.{Resource, Type}
  alias AshAuthentication.PasswordAuthentication, as: PA
  alias AshAuthentication.{GenerateTokenChange, Sender}
  alias Spark.Dsl.Transformer

  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action

  @doc false
  @impl true
  @spec transform(map) ::
          :ok
          | {:ok, map()}
          | {:error, term()}
          | {:warn, map(), String.t() | [String.t()]}
          | :halt
  def transform(dsl_state) do
    with :ok <- validate_extension(dsl_state, AshAuthentication),
         :ok <- validate_extension(dsl_state, PA),
         :ok <- validate_token_generation_enabled(dsl_state),
         {:ok, {sender, _opts}} <- Info.sender(dsl_state),
         :ok <- validate_behaviour(sender, Sender),
         {:ok, request_action_name} <- Info.request_password_reset_action_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             request_action_name,
             &build_request_action(&1, request_action_name)
           ),
         :ok <- validate_request_action(dsl_state, request_action_name),
         {:ok, change_action_name} <- Info.password_reset_action_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             change_action_name,
             &build_change_action(&1, change_action_name)
           ),
         :ok <- validate_change_action(dsl_state, change_action_name) do
      authentication =
        Transformer.get_persisted(dsl_state, :authentication)
        |> Map.update(
          :providers,
          [AshAuthentication.PasswordReset],
          &[AshAuthentication.PasswordReset | &1]
        )

      dsl_state =
        dsl_state
        |> Transformer.persist(:authentication, authentication)

      {:ok, dsl_state}
    else
      :error -> {:error, "Configuration error"}
      {:error, reason} -> {:error, reason}
    end
  end

  @doc false
  @impl true
  @spec after?(module) :: boolean
  def after?(AshAuthentication.Transformer), do: true
  def after?(PA.Transformer), do: true
  def after?(_), do: false

  @doc false
  @impl true
  @spec before?(module) :: boolean
  def before?(Resource.Transformers.DefaultAccept), do: true
  def before?(_), do: false

  defp build_request_action(dsl_state, action_name) do
    with {:ok, identity_field} <- PA.Info.password_authentication_identity_field(dsl_state) do
      identity_attribute = Resource.Info.attribute(dsl_state, identity_field)

      arguments = [
        Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
          name: identity_field,
          type: identity_attribute.type,
          allow_nil?: false
        )
      ]

      preparations = [
        Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
          preparation: RequestPasswordResetPreparation
        )
      ]

      Transformer.build_entity(Resource.Dsl, [:actions], :read,
        name: action_name,
        arguments: arguments,
        preparations: preparations
      )
    end
  end

  defp build_change_action(dsl_state, action_name) do
    with {:ok, password_field} <- PA.Info.password_authentication_password_field(dsl_state),
         {:ok, confirm_field} <-
           PA.Info.password_authentication_password_confirmation_field(dsl_state),
         confirmation_required? <-
           PA.Info.password_authentication_confirmation_required?(dsl_state) do
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
            Keyword.put(password_opts, :name, password_field)
          )
        ]
        |> maybe_append(
          confirmation_required?,
          Transformer.build_entity!(
            Resource.Dsl,
            [:actions, :update],
            :argument,
            Keyword.put(password_opts, :name, confirm_field)
          )
        )

      changes =
        [
          Transformer.build_entity!(Resource.Dsl, [:actions, :update], :validate,
            validation: ResetTokenValidation
          )
        ]
        |> maybe_append(
          confirmation_required?,
          Transformer.build_entity!(Resource.Dsl, [:actions, :update], :validate,
            validation: PA.PasswordConfirmationValidation
          )
        )
        |> Enum.concat([
          Transformer.build_entity!(Resource.Dsl, [:actions, :update], :change,
            change: PA.HashPasswordChange
          ),
          Transformer.build_entity!(Resource.Dsl, [:actions, :update], :change,
            change: GenerateTokenChange
          )
        ])

      Transformer.build_entity(Resource.Dsl, [:actions], :update,
        name: action_name,
        arguments: arguments,
        changes: changes,
        accept: []
      )
    end
  end

  defp validate_request_action(dsl_state, action_name) do
    with {:ok, action} <- validate_action_exists(dsl_state, action_name),
         {:ok, identity_field} <- PA.Info.password_authentication_identity_field(dsl_state),
         :ok <- PA.UserValidations.validate_identity_argument(dsl_state, action, identity_field) do
      validate_action_has_preparation(action, RequestPasswordResetPreparation)
    end
  end

  defp validate_change_action(dsl_state, action_name) do
    with {:ok, password_field} <- PA.Info.password_authentication_password_field(dsl_state),
         {:ok, password_confirmation_field} <-
           PA.Info.password_authentication_password_confirmation_field(dsl_state),
         confirmation_required? <-
           PA.Info.password_authentication_confirmation_required?(dsl_state),
         {:ok, action} <- validate_action_exists(dsl_state, action_name),
         :ok <- validate_action_has_validation(action, ResetTokenValidation),
         :ok <- validate_action_has_change(action, PA.HashPasswordChange),
         :ok <- PA.UserValidations.validate_password_argument(action, password_field),
         :ok <-
           PA.UserValidations.validate_password_confirmation_argument(
             action,
             password_confirmation_field,
             confirmation_required?
           ),
         :ok <-
           PA.UserValidations.validate_action_has_validation(
             action,
             PA.PasswordConfirmationValidation,
             confirmation_required?
           ) do
      validate_action_has_change(action, GenerateTokenChange)
    end
  end
end
