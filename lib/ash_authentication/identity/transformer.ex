defmodule AshAuthentication.Identity.Transformer do
  @moduledoc """
  The Identity Authentication transformer

  Scans the resource and checks that all the fields and actions needed are
  present.

  ## Future improvements.

  * Allow default constraints on password fields to be configurable.
  """

  use Spark.Dsl.Transformer
  alias Ash.Resource.Info

  alias AshAuthentication.Identity.{
    Config,
    GenerateTokenChange,
    HashPasswordChange,
    PasswordConfirmationValidation,
    SignInPreparation
  }

  alias Spark.Dsl.Transformer
  import AshAuthentication.Identity.UserValidations
  import AshAuthentication.Utils, only: [maybe_append: 3]

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
          [AshAuthentication.Identity],
          &[AshAuthentication.Identity | &1]
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
  def before?(_), do: false

  defp maybe_build_action(dsl_state, action_name, builder) when is_function(builder, 1) do
    with nil <- Info.action(dsl_state, action_name),
         {:ok, action} <- builder.(dsl_state) do
      {:ok, Transformer.add_entity(dsl_state, [:actions], action)}
    else
      action when is_map(action) -> {:ok, dsl_state}
      {:error, reason} -> {:error, reason}
    end
  end

  defp build_register_action(dsl_state) do
    with {:ok, identity_field} <- Config.identity_field(dsl_state),
         {:ok, password_field} <- Config.password_field(dsl_state),
         {:ok, confirm_field} <- Config.password_confirmation_field(dsl_state),
         {:ok, confirmation_required?} <- Config.confirmation_required?(dsl_state) do
      password_opts = [
        type: Ash.Type.String,
        allow_nil?: false,
        constraints: [min_length: 8],
        sensitive?: true
      ]

      arguments =
        [
          Transformer.build_entity!(
            Ash.Resource.Dsl,
            [:actions, :create],
            :argument,
            Keyword.put(password_opts, :name, password_field)
          )
        ]
        |> maybe_append(
          confirmation_required?,
          Transformer.build_entity!(
            Ash.Resource.Dsl,
            [:actions, :create],
            :argument,
            Keyword.put(password_opts, :name, confirm_field)
          )
        )

      changes =
        []
        |> maybe_append(
          confirmation_required?,
          Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :create], :validate,
            validation: PasswordConfirmationValidation
          )
        )
        |> Enum.concat([
          Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :create], :change,
            change: HashPasswordChange
          ),
          Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :create], :change,
            change: GenerateTokenChange
          )
        ])

      Transformer.build_entity(Ash.Resource.Dsl, [:actions], :create,
        name: :register,
        accept: [identity_field],
        arguments: arguments,
        changes: changes
      )
    end
  end

  def build_sign_in_action(dsl_state) do
    with {:ok, identity_field} <- Config.identity_field(dsl_state),
         {:ok, password_field} <- Config.password_field(dsl_state) do
      arguments = [
        Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :read], :argument,
          name: identity_field,
          type: Ash.Type.String,
          allow_nil?: false
        ),
        Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :read], :argument,
          name: password_field,
          type: Ash.Type.String,
          allow_nil?: false,
          sensitive?: true
        )
      ]

      preparations = [
        Transformer.build_entity!(Ash.Resource.Dsl, [:actions, :read], :prepare,
          preparation: SignInPreparation
        )
      ]

      Transformer.build_entity(Ash.Resource.Dsl, [:actions], :read,
        name: :sign_in,
        arguments: arguments,
        preparations: preparations,
        get?: true
      )
    end
  end
end
