defmodule AshAuthentication.PasswordAuthentication.Transformer do
  @moduledoc """
  The PasswordAuthentication Authentication transformer

  Scans the resource and checks that all the fields and actions needed are
  present.

  ## What it's looking for.

  In order for password authentication to work we need a few basic things to be present on the
  resource, but we _can_ generate almost everything we need, even if we do
  generate some actions, etc, we still must validate them because we want to
  allow the user to be able to overwrite as much as possible.

  You can manually implement as much (or as little) of these as you wish.

  Here's a (simplified) list of what it's validating:

  * The main `AshAuthentication` extension is present on the resource.
  * There is an identity field configured (either by the user or by default) and
    that a writable attribute with the same name of the appropriate type exists.
  * There is a hashed password field configured (either by the user or by
    default) and that a writable attribute with the same name of the appropriate
    type exists.
  * That the configured hash provider actually implements the
    `AshAuthentication.HashProvider` behaviour.
  * That there is a read action called `sign_in` (or other name based on
    configuration) and that it has the following properties:
    - it takes an argument of the same name and type as the configured identity
      field.
    - it takes an argument of the same name and type as the configured password
      field.
    - it has the `PasswordAuthentication.SignInPreparation` preparation present.
  * That there is a create action called `register` (or other name based on
    configuration) and that it has the following properties:
    - it takes an argument of the same name and type as the configured identity field.
    - it takes an argument of the same name and type as the configured password field.
    - it takes an argument of the same name and type as the configured password confirmation field if confirmation is enabled.
    - it has the `PasswordAuthentication.HashPasswordChange` change present.
    - it has the `PasswordAuthentication.GenerateTokenChange` change present.
    - it has the `PasswordAuthentication.PasswordConfirmationValidation` validation present.

  ## Future improvements.

  * Allow default constraints on password fields to be configurable.
  """

  use Spark.Dsl.Transformer

  alias AshAuthentication.PasswordAuthentication.{
    GenerateTokenChange,
    HashPasswordChange,
    Info,
    PasswordConfirmationValidation,
    SignInPreparation
  }

  alias Ash.{Resource, Type}
  alias Spark.Dsl.Transformer
  import AshAuthentication.PasswordAuthentication.UserValidations
  import AshAuthentication.Utils

  @doc false
  @impl true
  @spec transform(map) ::
          :ok
          | {:ok, map()}
          | {:error, term()}
          | {:warn, map(), String.t() | [String.t()]}
          | :halt
  def transform(dsl_state) do
    with :ok <- validate_authentication_extension(dsl_state),
         {:ok, dsl_state} <- validate_identity_field(dsl_state),
         {:ok, dsl_state} <- validate_hashed_password_field(dsl_state),
         {:ok, dsl_state} <- maybe_build_action(dsl_state, :register, &build_register_action/1),
         {:ok, dsl_state} <- validate_register_action(dsl_state),
         {:ok, dsl_state} <- maybe_build_action(dsl_state, :sign_in, &build_sign_in_action/1),
         {:ok, dsl_state} <- validate_sign_in_action(dsl_state),
         :ok <- validate_hash_provider(dsl_state) do
      authentication =
        Transformer.get_persisted(dsl_state, :authentication)
        |> Map.update(
          :providers,
          [AshAuthentication.PasswordAuthentication],
          &[AshAuthentication.PasswordAuthentication | &1]
        )

      dsl_state =
        dsl_state
        |> Transformer.persist(:authentication, authentication)

      {:ok, dsl_state}
    end
  end

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

  defp build_register_action(dsl_state) do
    with {:ok, hashed_password_field} <- Info.hashed_password_field(dsl_state),
         {:ok, password_field} <- Info.password_field(dsl_state),
         {:ok, confirm_field} <- Info.password_confirmation_field(dsl_state),
         confirmation_required? <- Info.confirmation_required?(dsl_state) do
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
            Keyword.put(password_opts, :name, password_field)
          )
        ]
        |> maybe_append(
          confirmation_required?,
          Transformer.build_entity!(
            Resource.Dsl,
            [:actions, :create],
            :argument,
            Keyword.put(password_opts, :name, confirm_field)
          )
        )

      changes =
        []
        |> maybe_append(
          confirmation_required?,
          Transformer.build_entity!(Resource.Dsl, [:actions, :create], :validate,
            validation: PasswordConfirmationValidation
          )
        )
        |> Enum.concat([
          Transformer.build_entity!(Resource.Dsl, [:actions, :create], :change,
            change: HashPasswordChange
          ),
          Transformer.build_entity!(Resource.Dsl, [:actions, :create], :change,
            change: GenerateTokenChange
          )
        ])

      Transformer.build_entity(Resource.Dsl, [:actions], :create,
        name: :register,
        arguments: arguments,
        changes: changes,
        allow_nil_input: [hashed_password_field]
      )
    end
  end

  defp build_sign_in_action(dsl_state) do
    with {:ok, identity_field} <- Info.identity_field(dsl_state),
         {:ok, password_field} <- Info.password_field(dsl_state) do
      identity_attribute = Resource.Info.attribute(dsl_state, identity_field)

      arguments = [
        Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
          name: identity_field,
          type: identity_attribute.type,
          allow_nil?: false
        ),
        Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
          name: password_field,
          type: Type.String,
          allow_nil?: false,
          sensitive?: true
        )
      ]

      preparations = [
        Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
          preparation: SignInPreparation
        )
      ]

      Transformer.build_entity(Resource.Dsl, [:actions], :read,
        name: :sign_in,
        arguments: arguments,
        preparations: preparations,
        get?: true
      )
    end
  end
end
