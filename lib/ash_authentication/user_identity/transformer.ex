defmodule AshAuthentication.UserIdentity.Transformer do
  @moduledoc """
  The user identity transformer.

  Sets up the default schema and actions for a user identity resource.
  """

  use Spark.Dsl.Transformer
  alias Ash.{Resource, Type}
  alias AshAuthentication.UserIdentity
  alias Spark.{Dsl.Transformer, Error.DslError}
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
  def before?(Resource.Transformers.ValidateRelationshipAttributes), do: true
  def before?(Resource.Transformers.BelongsToAttribute), do: true
  def before?(_), do: false

  @doc false
  @impl true
  @spec transform(map) ::
          :ok | {:ok, map} | {:error, term} | {:warn, map, String.t() | [String.t()]} | :halt
  def transform(dsl_state) do
    with {:ok, dsl_state} <- maybe_set_domain(dsl_state, :user_identity),
         {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, :id, Type.UUID,
             allow_nil?: false,
             writable?: true,
             primary_key?: true,
             default: &Ash.UUID.generate/0
           ),
         :ok <- validate_id_field(dsl_state, :id),
         {:ok, uid} <- UserIdentity.Info.user_identity_uid_attribute_name(dsl_state),
         {:ok, strategy} <-
           UserIdentity.Info.user_identity_strategy_attribute_name(dsl_state),
         {:ok, user_id} <-
           UserIdentity.Info.user_identity_user_id_attribute_name(dsl_state),
         {:ok, access_token} <-
           UserIdentity.Info.user_identity_access_token_attribute_name(dsl_state),
         {:ok, access_token_expires_at} <-
           UserIdentity.Info.user_identity_access_token_expires_at_attribute_name(dsl_state),
         {:ok, refresh_token} <-
           UserIdentity.Info.user_identity_refresh_token_attribute_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, strategy, Type.String,
             allow_nil?: false,
             writable?: true,
             public?: true
           ),
         :ok <- validate_strategy_field(dsl_state, strategy),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, uid, Type.String, allow_nil?: false, writable?: true),
         :ok <- validate_uid_field(dsl_state, uid),
         {:ok, dsl_state} <- maybe_build_identity(dsl_state, [user_id, uid, strategy]),
         :ok <-
           validate_attribute_unique_constraint(dsl_state, [user_id, uid, strategy], resource),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, access_token, Type.String,
             allow_nil?: true,
             writable?: true
           ),
         :ok <- validate_token_field(dsl_state, access_token),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, access_token_expires_at, Type.UtcDatetimeUsec,
             allow_nil?: true,
             writable?: true
           ),
         :ok <- validate_expiry_field(dsl_state, access_token_expires_at),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, refresh_token, Type.String,
             allow_nil?: true,
             writable?: true
           ),
         :ok <- validate_token_field(dsl_state, refresh_token),
         {:ok, user_resource} <- UserIdentity.Info.user_identity_user_resource(dsl_state),
         {:ok, user_relationship} <-
           UserIdentity.Info.user_identity_user_relationship_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_relationship(
             dsl_state,
             user_relationship,
             &build_user_relationship(&1, user_relationship, user_resource)
           ),
         :ok <- validate_user_relationship(dsl_state, user_relationship, user_resource),
         {:ok, upsert_action} <-
           UserIdentity.Info.user_identity_upsert_action_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_action(dsl_state, upsert_action, &build_upsert_action(&1, upsert_action)),
         :ok <- validate_upsert_action(dsl_state, upsert_action),
         {:ok, destroy_action} <-
           UserIdentity.Info.user_identity_destroy_action_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_action(
             dsl_state,
             destroy_action,
             &build_destroy_action(&1, destroy_action)
           ),
         :ok <-
           validate_destroy_action(dsl_state, destroy_action),
         {:ok, read_action} <-
           UserIdentity.Info.user_identity_read_action_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_action(dsl_state, read_action, &build_read_action(&1, read_action)),
         :ok <- validate_read_action(dsl_state, read_action) do
      {:ok, dsl_state}
    end
  end

  defp validate_id_field(dsl_state, field_name) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, field_name),
         :ok <- validate_attribute_option(attribute, resource, :primary_key?, [true]) do
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_strategy_field(dsl_state, field_name) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, field_name),
         :ok <- validate_attribute_option(attribute, resource, :type, [Type.String, :string]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :public?, [true]) do
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_uid_field(dsl_state, field_name) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, field_name),
         :ok <- validate_attribute_option(attribute, resource, :type, [Type.String, :string]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [false]),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]) do
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_token_field(dsl_state, field_name) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, field_name),
         :ok <- validate_attribute_option(attribute, resource, :type, [Type.String, :string]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]) do
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp validate_expiry_field(dsl_state, field_name) do
    with {:ok, resource} <- persisted_option(dsl_state, :module),
         {:ok, attribute} <- find_attribute(dsl_state, field_name),
         :ok <-
           validate_attribute_option(attribute, resource, :type, [
             Type.UtcDatetimeUsec,
             :utc_datetime_usec
           ]),
         :ok <- validate_attribute_option(attribute, resource, :allow_nil?, [true]),
         :ok <- validate_attribute_option(attribute, resource, :writable?, [true]) do
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp build_user_relationship(dsl_state, name, destination) do
    with {:ok, id_attr} <- find_pk(destination),
         {:ok, domain} <- AshAuthentication.Info.domain(destination),
         {:ok, user_id} <-
           UserIdentity.Info.user_identity_user_id_attribute_name(dsl_state) do
      Transformer.build_entity(Resource.Dsl, [:relationships], :belongs_to,
        name: name,
        destination: destination,
        define_attribute?: true,
        destination_attribute: id_attr.name,
        attribute_type: id_attr.type,
        source_attribute: user_id,
        domain: domain,
        attribute_writable?: true,
        writable?: true
      )
    end
  end

  defp validate_user_relationship(dsl_state, name, destination) do
    with {:ok, id_attr} <- find_pk(destination),
         {:ok, domain} <- AshAuthentication.Info.domain(destination),
         {:ok, relationship} <- find_relationship(dsl_state, name),
         {:ok, user_id} <-
           UserIdentity.Info.user_identity_user_id_attribute_name(dsl_state),
         :ok <- validate_field_in_values(relationship, :destination, [destination]),
         :ok <- validate_field_in_values(relationship, :destination_attribute, [id_attr.name]),
         :ok <- validate_field_in_values(relationship, :source_attribute, [user_id]),
         :ok <- validate_field_in_values(relationship, :domain, [domain]) do
      validate_field_in_values(relationship, :attribute_type, [id_attr.type])
    end
  end

  defp build_upsert_action(dsl_state, action_name) do
    with {:ok, user_id} <-
           UserIdentity.Info.user_identity_user_id_attribute_name(dsl_state),
         {:ok, uid} <- UserIdentity.Info.user_identity_uid_attribute_name(dsl_state),
         {:ok, strategy} <-
           UserIdentity.Info.user_identity_strategy_attribute_name(dsl_state),
         {:ok, identity} <- find_identity(dsl_state, [user_id, uid, strategy]),
         {:ok, user_resource} <- UserIdentity.Info.user_identity_user_resource(dsl_state),
         {:ok, user_resource_id} <- find_pk(user_resource) do
      arguments = [
        Transformer.build_entity!(Resource.Dsl, [:actions, :create], :argument,
          name: :user_info,
          type: Type.Map,
          allow_nil?: false
        ),
        Transformer.build_entity!(Resource.Dsl, [:actions, :create], :argument,
          name: :oauth_tokens,
          type: Type.Map,
          allow_nil?: false
        ),
        Transformer.build_entity!(Resource.Dsl, [:actions, :create], :argument,
          name: user_id,
          type: user_resource_id.type,
          allow_nil?: false
        )
      ]

      changes = [
        Transformer.build_entity!(Resource.Dsl, [:actions, :create], :change,
          change: UserIdentity.UpsertIdentityChange
        )
      ]

      Transformer.build_entity(Resource.Dsl, [:actions], :create,
        name: action_name,
        upsert?: true,
        upsert_identity: identity.name,
        arguments: arguments,
        changes: changes,
        accept: [strategy]
      )
    end
  end

  defp validate_upsert_action(dsl_state, action_name) do
    with {:ok, action} <- validate_action_exists(dsl_state, action_name),
         :ok <- validate_action_argument_option(action, :user_info, :type, [:map, Type.Map]),
         :ok <- validate_action_argument_option(action, :user_info, :allow_nil?, [false]),
         :ok <- validate_action_argument_option(action, :oauth_tokens, :type, [:map, Type.Map]),
         :ok <- validate_action_argument_option(action, :oauth_tokens, :allow_nil?, [false]),
         :ok <- validate_action_has_change(action, UserIdentity.UpsertIdentityChange),
         :ok <- validate_field_in_values(action, :type, [:create]),
         :ok <- validate_field_in_values(action, :upsert?, [true]),
         {:ok, user_id} <-
           UserIdentity.Info.user_identity_user_id_attribute_name(dsl_state),
         {:ok, user_resource} <- UserIdentity.Info.user_identity_user_resource(dsl_state),
         {:ok, user_resource_id} <- find_pk(user_resource),
         :ok <- validate_action_argument_option(action, user_id, :type, [user_resource_id.type]),
         :ok <- validate_action_argument_option(action, user_id, :allow_nil?, [false]),
         {:ok, uid} <- UserIdentity.Info.user_identity_uid_attribute_name(dsl_state),
         {:ok, strategy} <-
           UserIdentity.Info.user_identity_strategy_attribute_name(dsl_state),
         {:ok, identity} <- find_identity(dsl_state, [uid, user_id, strategy]),
         :ok <- validate_field_in_values(action, :upsert_identity, [identity.name]) do
      :ok
    else
      {:error, reason} when is_binary(reason) ->
        {:error, DslError.exception(path: [:user_identity], message: reason)}

      {:error, reason} ->
        {:error, reason}

      :error ->
        {:error,
         DslError.exception(
           path: [:user_identity],
           message: "Configuration error while validating upsert action."
         )}
    end
  end

  defp build_destroy_action(_dsl_state, action_name) do
    Transformer.build_entity(Resource.Dsl, [:actions], :destroy,
      name: action_name,
      primary?: true
    )
  end

  defp validate_destroy_action(dsl_state, action_name) do
    with {:ok, action} <- validate_action_exists(dsl_state, action_name),
         :ok <- validate_field_in_values(action, :type, [:destroy]),
         :ok <- validate_field_in_values(action, :primary?, [true]) do
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp build_read_action(_dsl_state, action_name) do
    Transformer.build_entity(Resource.Dsl, [:actions], :read, name: action_name, primary?: true)
  end

  defp validate_read_action(dsl_state, action_name) do
    with {:ok, action} <- validate_action_exists(dsl_state, action_name),
         :ok <- validate_field_in_values(action, :type, [:read]),
         :ok <- validate_field_in_values(action, :primary?, [true]) do
      :ok
    else
      {:error, reason} -> {:error, reason}
    end
  end

  defp find_identity(dsl_state, keys) do
    keyset = MapSet.new(keys)

    dsl_state
    |> Resource.Info.identities()
    |> Enum.find_value(:error, fn identity ->
      if MapSet.equal?(MapSet.new(identity.keys), keyset), do: {:ok, identity}
    end)
  end

  # sobelow_skip ["DOS.StringToAtom"]
  defp maybe_build_identity(dsl_state, keys) do
    dsl_state
    |> find_identity(keys)
    |> case do
      {:ok, _identity} ->
        {:ok, dsl_state}

      :error ->
        keys = Enum.sort(keys)

        name =
          keys
          |> Enum.join("_and_")
          |> then(&"unique_on_#{&1}")
          |> String.to_atom()

        identity =
          Transformer.build_entity!(Resource.Dsl, [:identities], :identity,
            name: name,
            keys: keys
          )

        {:ok, Transformer.add_entity(dsl_state, [:identities], identity)}
    end
  end

  defp find_pk(resource) do
    with [id_field] <- Resource.Info.primary_key(resource),
         id_attr when is_map(id_attr) <- Resource.Info.attribute(resource, id_field) do
      {:ok, id_attr}
    else
      nopk when nopk == [] or is_nil(nopk) ->
        {:error, "`#{inspect(resource)}` must have a primary key."}

      [_ | _] ->
        {:error, "Resources with composite primary keys are not supported."}

      _other ->
        {:error, "Unable to retrieve primary key for resource `#{inspect(resource)}`."}
    end
  end
end
