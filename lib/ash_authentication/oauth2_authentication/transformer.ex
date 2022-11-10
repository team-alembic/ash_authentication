defmodule AshAuthentication.OAuth2Authentication.Transformer do
  @moduledoc """
  The OAuth2Authentication Authentication transformer.

  Scans the resource and checks that all the fields and actions needed are
  present.
  """

  use Spark.Dsl.Transformer

  alias Ash.Resource
  alias AshAuthentication.GenerateTokenChange
  alias AshAuthentication.OAuth2Authentication, as: OAuth2
  alias Spark.{Dsl.Transformer, Error.DslError}

  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action
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
    with :ok <- validate_extension(dsl_state, AshAuthentication),
         {:ok, identity_resource} <- OAuth2.Info.identity_resource(dsl_state),
         {:ok, dsl_state} <- maybe_build_identity_relationship(dsl_state, identity_resource),
         {:ok, dsl_state} <-
           maybe_set_action_name(dsl_state, :register_action_name, "register_with_"),
         {:ok, register_action_name} <- OAuth2.Info.register_action_name(dsl_state),
         registration_enabled? <- OAuth2.Info.registration_enabled?(dsl_state),
         :ok <- validate_register_action(dsl_state, register_action_name, registration_enabled?),
         {:ok, dsl_state} <-
           maybe_set_action_name(dsl_state, :sign_in_action_name, "sign_in_with_"),
         {:ok, sign_in_action_name} <- OAuth2.Info.sign_in_action_name(dsl_state),
         sign_in_enabled? <- OAuth2.Info.sign_in_enabled?(dsl_state),
         :ok <- validate_sign_in_action(dsl_state, sign_in_action_name, sign_in_enabled?),
         :ok <- validate_only_one_action_enabled(dsl_state) do
      authentication =
        Transformer.get_persisted(dsl_state, :authentication)
        |> Map.update(
          :providers,
          [AshAuthentication.OAuth2Authentication],
          &[AshAuthentication.OAuth2Authentication | &1]
        )

      dsl_state =
        dsl_state
        |> Transformer.persist(:authentication, authentication)

      {:ok, dsl_state}
    else
      {:error, reason} when is_binary(reason) ->
        {:error, DslError.exception(path: [:oauth2_authentication], message: reason)}

      {:error, reason} ->
        {:error, reason}

      :error ->
        {:error,
         DslError.exception(
           path: [:oauth2_authentication],
           message: "Configuration error while validating `oauth2_authentication`."
         )}
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
  def before?(Resource.Transformers.HasDestinationField), do: true
  def before?(Resource.Transformers.SetRelationshipSource), do: true
  def before?(Resource.Transformers.ValidateRelationshipAttributes), do: true
  def before?(_), do: false

  defp validate_only_one_action_enabled(dsl_state) do
    registration_enabled? = OAuth2.Info.registration_enabled?(dsl_state)
    sign_in_enabled? = OAuth2.Info.sign_in_enabled?(dsl_state)

    case {registration_enabled?, sign_in_enabled?} do
      {true, true} ->
        {:error, "Only one of `registration_enabled?` and `sign_in_enabled?` can be set."}

      {false, false} ->
        {:error, "One of either `registration_enabled?` and `sign_in_enabled?` must be set."}

      _ ->
        :ok
    end
  end

  defp maybe_set_action_name(dsl_state, option, prefix) do
    cfg = OAuth2.Info.options(dsl_state)

    case Map.fetch(cfg, option) do
      {:ok, _value} ->
        {:ok, dsl_state}

      :error ->
        action_name = String.to_atom("#{prefix}#{cfg.provider_name}")
        {:ok, Transformer.set_option(dsl_state, [:oauth2_authentication], option, action_name)}
    end
  end

  defp maybe_build_identity_relationship(dsl_state, falsy) when is_falsy(falsy),
    do: {:ok, dsl_state}

  defp maybe_build_identity_relationship(dsl_state, identity_resource) do
    with {:ok, identity_relationship} <- OAuth2.Info.identity_relationship_name(dsl_state) do
      maybe_build_relationship(
        dsl_state,
        identity_relationship,
        &build_identity_relationship(&1, identity_relationship, identity_resource)
      )
    end
  end

  defp validate_register_action(_dsl_state, _action_name, false), do: :ok

  defp validate_register_action(dsl_state, action_name, true) do
    with {:ok, action} <- validate_action_exists(dsl_state, action_name),
         :ok <- validate_action_has_argument(action, :user_info),
         :ok <- validate_action_argument_option(action, :user_info, :type, [Ash.Type.Map, :map]),
         :ok <- validate_action_argument_option(action, :user_info, :allow_nil?, [false]),
         :ok <- validate_action_has_argument(action, :oauth_tokens),
         :ok <-
           validate_action_argument_option(action, :oauth_tokens, :type, [Ash.Type.Map, :map]),
         :ok <- validate_action_argument_option(action, :oauth_tokens, :allow_nil?, [false]),
         :ok <- maybe_validate_action_has_token_change(dsl_state, action),
         :ok <- validate_field_in_values(action, :upsert?, [true]),
         :ok <-
           validate_field_with(
             action,
             :upsert_identity,
             &(is_atom(&1) and not is_falsy(&1)),
             "Expected `upsert_identity` to be set"
           ),
         {:ok, identity_resource} <- OAuth2.Info.identity_resource(dsl_state),
         :ok <- maybe_validate_action_has_identity_change(action, identity_resource) do
      :ok
    else
      :error ->
        {:error, "Unable to validate register action"}

      {:error, reason} when is_binary(reason) ->
        {:error, "`#{inspect(action_name)}` action: #{reason}"}

      {:error, reason} ->
        {:error, reason}
    end
  end

  defp validate_sign_in_action(_dsl_state, _action_name, false), do: :ok

  defp validate_sign_in_action(dsl_state, action_name, true) do
    with {:ok, action} <- validate_action_exists(dsl_state, action_name),
         :ok <- validate_action_has_argument(action, :user_info),
         :ok <- validate_action_argument_option(action, :user_info, :type, [Ash.Type.Map, :map]),
         :ok <- validate_action_argument_option(action, :user_info, :allow_nil?, [false]),
         :ok <- validate_action_has_argument(action, :oauth_tokens),
         :ok <-
           validate_action_argument_option(action, :oauth_tokens, :type, [Ash.Type.Map, :map]),
         :ok <- validate_action_argument_option(action, :oauth_tokens, :allow_nil?, [false]),
         :ok <- validate_action_has_preparation(action, OAuth2.SignInPreparation) do
      :ok
    else
      :error -> {:error, "Unable to validate sign in action"}
      {:error, reason} -> {:error, reason}
    end
  end

  defp maybe_validate_action_has_token_change(dsl_state, action) do
    if AshAuthentication.Info.tokens_enabled?(dsl_state) do
      validate_action_has_change(action, GenerateTokenChange)
    else
      :ok
    end
  end

  defp build_identity_relationship(dsl_state, name, destination) do
    with {:ok, dest_attr} <- OAuth2.Info.identity_relationship_user_id_attribute(dsl_state) do
      Transformer.build_entity(Resource.Dsl, [:relationships], :has_many,
        name: name,
        destination: destination,
        destination_attribute: dest_attr
      )
    end
  end

  defp maybe_validate_action_has_identity_change(_action, falsy) when is_falsy(falsy), do: :ok

  defp maybe_validate_action_has_identity_change(action, _identity_resource),
    do: validate_action_has_change(action, OAuth2.IdentityChange)
end
