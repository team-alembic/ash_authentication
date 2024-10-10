defmodule AshAuthentication.TokenResource.Transformer do
  @moduledoc """
  The token resource transformer.

  Sets up the default schema and actions for the token resource.
  """

  use Spark.Dsl.Transformer
  require Ash.Expr
  alias Ash.{Resource, Type}
  alias AshAuthentication.{TokenResource, TokenResource.Info}
  alias Spark.Dsl.Transformer
  alias Spark.Error.DslError

  import AshAuthentication.Utils
  import AshAuthentication.Validations
  import AshAuthentication.Validations.Action
  import AshAuthentication.Validations.Attribute

  @doc false
  @impl true
  @spec after?(any) :: boolean()
  def after?(Resource.Transformers.ValidatePrimaryActions), do: true
  def after?(_), do: false

  @doc false
  @impl true
  @spec before?(any) :: boolean
  def before?(Resource.Transformers.CachePrimaryKey), do: true
  def before?(Resource.Transformers.DefaultAccept), do: true
  def before?(_), do: false

  @doc false
  @impl true
  @spec transform(map) ::
          :ok | {:ok, map} | {:error, term} | {:warn, map, String.t() | [String.t()]} | :halt
  def transform(dsl_state) do
    with {:ok, dsl_state} <- maybe_set_domain(dsl_state, :token),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, :jti, :string,
             primary_key?: true,
             allow_nil?: false,
             sensitive?: true,
             writable?: true,
             public?: true
           ),
         :ok <- validate_jti_field(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, :subject, :string, allow_nil?: false, writable?: true),
         :ok <- validate_subject_field(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, :expires_at, :utc_datetime,
             allow_nil?: false,
             writable?: true
           ),
         :ok <- validate_expires_at_field(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, :purpose, :string,
             allow_nil?: false,
             writable?: true,
             public?: true
           ),
         :ok <- validate_purpose_field(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, :extra_data, :map,
             allow_nil?: true,
             writable?: true,
             public?: true
           ),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, :created_at, :utc_datetime_usec,
             allow_nil?: false,
             public?: false,
             default: &DateTime.utc_now/0
           ),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, :updated_at, :utc_datetime_usec,
             allow_nil?: false,
             public?: false,
             default: &DateTime.utc_now/0,
             update_default: &DateTime.utc_now/0
           ),
         :ok <- validate_extra_data_field(dsl_state),
         {:ok, expunge_expired_action_name} <- Info.token_expunge_expired_action_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             expunge_expired_action_name,
             &build_expunge_expired_action(&1, expunge_expired_action_name)
           ),
         :ok <- validate_expunge_expired_action(dsl_state, expunge_expired_action_name),
         {:ok, read_expired_action_name} <- Info.token_read_expired_action_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             read_expired_action_name,
             &build_read_expired_action(&1, read_expired_action_name)
           ),
         :ok <- validate_read_expired_action(dsl_state, read_expired_action_name),
         {:ok, revoke_token_action_name} <-
           Info.token_revocation_revoke_token_action_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             revoke_token_action_name,
             &build_revoke_token_action(&1, revoke_token_action_name)
           ),
         :ok <- validate_revoke_token_action(dsl_state, revoke_token_action_name),
         {:ok, is_revoked_action_name} <- Info.token_revocation_is_revoked_action_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             is_revoked_action_name,
             &build_is_revoked_action(&1, is_revoked_action_name)
           ),
         :ok <- validate_is_revoked_action(dsl_state, is_revoked_action_name),
         {:ok, get_confirmation_changes_action_name} <-
           Info.token_confirmation_get_changes_action_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             get_confirmation_changes_action_name,
             &build_get_confirmation_changes_action(&1, get_confirmation_changes_action_name)
           ),
         :ok <-
           validate_get_confirmation_changes_action(
             dsl_state,
             get_confirmation_changes_action_name
           ),
         {:ok, store_confirmation_changes_action_name} <-
           Info.token_confirmation_store_changes_action_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             store_confirmation_changes_action_name,
             &build_store_confirmation_changes_action(&1, store_confirmation_changes_action_name)
           ),
         :ok <-
           validate_store_confirmation_changes_action(
             dsl_state,
             store_confirmation_changes_action_name
           ),
         {:ok, store_token_action_name} <-
           Info.token_store_token_action_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             store_token_action_name,
             &build_store_token_action(&1, store_token_action_name)
           ),
         :ok <- validate_store_token_action(dsl_state, store_token_action_name),
         {:ok, get_token_action_name} <- Info.token_get_token_action_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             get_token_action_name,
             &build_get_token_action(&1, get_token_action_name)
           ),
         :ok <- validate_get_token_action(dsl_state, get_token_action_name) do
      {:ok, dsl_state}
    end
  end

  defp validate_subject_field(dsl_state) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, :subject),
         :ok <- validate_attribute_option(attribute, resource, :type, [Type.String, :string]) do
      validate_attribute_option(attribute, resource, :writable?, [true])
    end
  end

  defp validate_get_token_action(dsl_state, action_name) do
    with {:ok, action} <- validate_action_exists(dsl_state, action_name),
         :ok <-
           validate_action_argument_option(action, :token, :type, [Ash.Type.String, :string]),
         :ok <- validate_action_argument_option(action, :token, :allow_nil?, [true]),
         :ok <- validate_action_argument_option(action, :token, :sensitive?, [true]),
         :ok <- validate_action_argument_option(action, :jti, :type, [Ash.Type.String, :string]),
         :ok <- validate_action_argument_option(action, :jti, :allow_nil?, [true]),
         :ok <-
           validate_action_argument_option(action, :purpose, :type, [Ash.Type.String, :string]) do
      validate_action_has_preparation(action, TokenResource.GetTokenPreparation)
    end
  end

  defp build_get_token_action(_dsl_state, action_name) do
    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: :token,
        type: :string,
        sensitive?: true
      ),
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: :jti,
        type: :string,
        sensitive?: true
      ),
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: :purpose,
        type: :string,
        sensitive?: false
      )
    ]

    preparations = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
        preparation: TokenResource.GetTokenPreparation
      )
    ]

    Transformer.build_entity(Resource.Dsl, [:actions], :read,
      name: action_name,
      arguments: arguments,
      preparations: preparations,
      get?: true
    )
  end

  defp validate_store_token_action(dsl_state, action_name) do
    with {:ok, action} <- validate_action_exists(dsl_state, action_name),
         :ok <- validate_token_argument(action) do
      validate_action_has_change(action, TokenResource.StoreTokenChange)
    end
  end

  defp build_store_token_action(_dsl_state, action_name) do
    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :argument,
        name: :token,
        type: :string,
        allow_nil?: false,
        sensitive?: true
      )
    ]

    changes = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :change,
        change: TokenResource.StoreTokenChange
      )
    ]

    Transformer.build_entity(Resource.Dsl, [:actions], :create,
      name: action_name,
      arguments: arguments,
      changes: changes,
      accept: [:extra_data, :purpose]
    )
  end

  defp build_store_confirmation_changes_action(_dsl_state, action_name) do
    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :argument,
        name: :token,
        type: :string,
        allow_nil?: false,
        sensitive?: true
      )
    ]

    changes = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :change,
        change: TokenResource.StoreConfirmationChangesChange
      )
    ]

    Transformer.build_entity(Resource.Dsl, [:actions], :create,
      name: action_name,
      arguments: arguments,
      changes: changes,
      accept: [:extra_data, :purpose]
    )
  end

  defp validate_store_confirmation_changes_action(dsl_state, action_name) do
    with {:ok, action} <- validate_action_exists(dsl_state, action_name),
         :ok <- validate_token_argument(action) do
      validate_action_has_change(action, TokenResource.StoreConfirmationChangesChange)
    end
  end

  defp build_get_confirmation_changes_action(_dsl_state, action_name) do
    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: :jti,
        type: :string,
        allow_nil?: false,
        sensitive?: true
      )
    ]

    preparations = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
        preparation: TokenResource.GetConfirmationChangesPreparation
      )
    ]

    Transformer.build_entity(Resource.Dsl, [:actions], :read,
      name: action_name,
      arguments: arguments,
      preparations: preparations,
      get?: true
    )
  end

  defp validate_get_confirmation_changes_action(dsl_state, action_name) do
    with {:ok, action} <- validate_action_exists(dsl_state, action_name),
         :ok <- validate_action_argument_option(action, :jti, :type, [Ash.Type.String, :string]),
         :ok <-
           validate_action_has_preparation(
             action,
             TokenResource.GetConfirmationChangesPreparation
           ) do
      validate_field_in_values(action, :type, [:read])
    end
  end

  defp build_read_expired_action(_dsl_state, action_name) do
    import Ash.Expr

    filter =
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :filter,
        filter: expr(expires_at < now())
      )

    Transformer.build_entity(Resource.Dsl, [:actions], :read,
      name: action_name,
      filters: [filter]
    )
  end

  defp validate_read_expired_action(dsl_state, action_name) do
    with {:ok, action} <- validate_action_exists(dsl_state, action_name) do
      validate_field_in_values(action, :type, [:read])
    end
  end

  defp validate_is_revoked_action(dsl_state, action_name) do
    case validate_action_exists(dsl_state, action_name) do
      {:ok, %{type: :read} = action} ->
        with :ok <-
               validate_action_argument_option(action, :token, :type, [Ash.Type.String, :string]),
             :ok <-
               validate_action_argument_option(action, :jti, :type, [Ash.Type.String, :string]) do
          validate_action_has_preparation(action, TokenResource.IsRevokedPreparation)
        end

      {:ok, %{type: :action} = action} ->
        with :ok <-
               validate_action_argument_option(action, :token, :type, [Ash.Type.String, :string]) do
          validate_action_argument_option(action, :jti, :type, [Ash.Type.String, :string])
        end

      {:ok, _} ->
        {:error,
         DslError.exception(
           module: Transformer.get_persisted(dsl_state, :module),
           path: [:actions, :is_revoked],
           message: "The action `:is_revoked` must be a read action or a generic action"
         )}

      _ ->
        :ok
    end
  end

  defp build_is_revoked_action(_dsl_state, action_name) do
    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: :token,
        type: :string,
        allow_nil?: true,
        sensitive?: true
      ),
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :argument,
        name: :jti,
        type: :string,
        allow_nil?: true,
        sensitive?: true
      )
    ]

    preparations = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :read], :prepare,
        preparation: TokenResource.IsRevokedPreparation
      )
    ]

    Transformer.build_entity(Resource.Dsl, [:actions], :read,
      name: action_name,
      get?: true,
      preparations: preparations,
      arguments: arguments
    )
  end

  defp validate_token_argument(action) do
    with :ok <-
           validate_action_argument_option(action, :token, :type, [Ash.Type.String, :string]),
         :ok <- validate_action_argument_option(action, :token, :allow_nil?, [false]) do
      validate_action_argument_option(action, :token, :sensitive?, [true])
    end
  end

  defp validate_revoke_token_action(dsl_state, revoke_token_action_name) do
    with {:ok, action} <- validate_action_exists(dsl_state, revoke_token_action_name),
         :ok <- validate_token_argument(action) do
      validate_action_has_change(action, TokenResource.RevokeTokenChange)
    end
  end

  defp build_revoke_token_action(_dsl_state, action_name) do
    arguments = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :argument,
        name: :token,
        type: :string,
        allow_nil?: false,
        sensitive?: true
      )
    ]

    changes = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :create], :change,
        change: TokenResource.RevokeTokenChange
      )
    ]

    Transformer.build_entity(Resource.Dsl, [:actions], :create,
      name: action_name,
      arguments: arguments,
      changes: changes,
      accept: [:extra_data]
    )
  end

  defp validate_expunge_expired_action(dsl_state, action_name) do
    with {:ok, action} <- validate_action_exists(dsl_state, action_name) do
      validate_field_in_values(action, :type, [:destroy])
    end
  end

  defp build_expunge_expired_action(_dsl_state, action_name) do
    import Ash.Expr

    changes = [
      Transformer.build_entity!(Resource.Dsl, [:actions, :destroy], :change,
        change: {Ash.Resource.Change.Filter, filter: expr(expires_at < now())}
      )
    ]

    Transformer.build_entity(Resource.Dsl, [:actions], :destroy,
      name: action_name,
      changes: changes
    )
  end

  defp validate_jti_field(dsl_state) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, :jti),
         :ok <- validate_attribute_option(attribute, resource, :type, [Type.String, :string]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]),
         :ok <- validate_attribute_option(attribute, resource, :sensitive?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :primary_key?, [true]) do
      validate_attribute_option(attribute, resource, :public?, [true])
    end
  end

  defp validate_expires_at_field(dsl_state) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, :expires_at),
         :ok <-
           validate_attribute_option(attribute, resource, :type, [Type.UtcDatetime, :utc_datetime]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]) do
      validate_attribute_option(attribute, resource, :writable?, [true])
    end
  end

  defp validate_purpose_field(dsl_state) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, :purpose),
         :ok <- validate_attribute_option(attribute, resource, :type, [Type.String, :string]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]) do
      validate_attribute_option(attribute, resource, :public?, [true])
    end
  end

  defp validate_extra_data_field(dsl_state) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, :extra_data),
         :ok <- validate_attribute_option(attribute, resource, :type, [Type.Map, :map]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]) do
      validate_attribute_option(attribute, resource, :public?, [true])
    end
  end
end
