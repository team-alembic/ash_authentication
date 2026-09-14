# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.WebAuthnCredential.Transformer do
  @moduledoc """
  DSL transformer for the `AshAuthentication.WebAuthnCredential` extension.

  Scaffolds the required attributes, `belongs_to` relationship, unique
  identity, and actions on the credential resource — building each one only
  if the user hasn't already declared it themselves — and validates the
  shape of whichever ones (built or user-declared) end up on the resource.

  This validation deliberately lives in the transformer rather than in a
  `Spark.Dsl.Verifier`: none of it needs another module to already be
  compiled (unlike, say, checking that a *different* resource accepts this
  one), so there's no reason to defer it to `@after_verify`. Doing it here
  means a misconfiguration is a synchronous compile error, in the same pass
  that builds the DSL state, rather than a background check that can run
  after the fact.
  """

  use Spark.Dsl.Transformer

  import AshAuthentication.Utils
  import AshAuthentication.Validations, only: [find_attribute: 2]

  alias Ash.Resource
  alias Spark.Dsl.Transformer
  alias Spark.Error.DslError

  alias AshAuthentication.Strategy.WebAuthn.CoseKey
  alias AshAuthentication.WebAuthnCredential.Info

  @doc false
  @impl Transformer
  def after?(_), do: false

  @doc false
  @impl Transformer
  def before?(Resource.Transformers.BelongsToAttribute), do: true
  def before?(Resource.Transformers.CachePrimaryKey), do: true
  def before?(Resource.Transformers.DefaultAccept), do: true
  def before?(Resource.Transformers.ValidateRelationshipAttributes), do: true
  def before?(_), do: false

  @doc false
  @impl Transformer
  def transform(dsl_state) do
    with :ok <- validate_wax_dependency(),
         {:ok, credential_id_field} <- Info.webauthn_credential_credential_id_field(dsl_state),
         {:ok, public_key_field} <- Info.webauthn_credential_public_key_field(dsl_state),
         {:ok, sign_count_field} <- Info.webauthn_credential_sign_count_field(dsl_state),
         {:ok, user_handle_field} <- Info.webauthn_credential_user_handle_field(dsl_state),
         {:ok, transports_field} <- Info.webauthn_credential_transports_field(dsl_state),
         {:ok, backup_eligible_field} <-
           Info.webauthn_credential_backup_eligible_field(dsl_state),
         {:ok, backed_up_field} <- Info.webauthn_credential_backed_up_field(dsl_state),
         {:ok, discoverable_field} <- Info.webauthn_credential_discoverable_field(dsl_state),
         {:ok, label_field} <- Info.webauthn_credential_label_field(dsl_state),
         {:ok, last_used_at_field} <- Info.webauthn_credential_last_used_at_field(dsl_state),
         {:ok, user_id_field} <- Info.webauthn_credential_user_id_field(dsl_state),
         {:ok, user_resource} <- Info.webauthn_credential_user_resource(dsl_state),
         {:ok, user_relationship_name} <-
           Info.webauthn_credential_user_relationship_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_relationship(
             dsl_state,
             user_relationship_name,
             &build_user_relationship(&1, user_relationship_name, user_resource, user_id_field)
           ),
         :ok <- validate_user_relationship(dsl_state, user_relationship_name, user_resource),
         user_id_field <-
           resolve_user_id_field(dsl_state, user_relationship_name, user_id_field),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, credential_id_field, :binary,
             allow_nil?: false,
             writable?: true,
             public?: true
           ),
         :ok <- validate_attribute(dsl_state, credential_id_field, :binary, allow_nil?: false),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, public_key_field, CoseKey,
             allow_nil?: false,
             writable?: true,
             public?: true
           ),
         :ok <- validate_attribute(dsl_state, public_key_field, CoseKey, allow_nil?: false),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, sign_count_field, :integer,
             allow_nil?: false,
             default: 0,
             writable?: true,
             public?: true
           ),
         :ok <- validate_attribute(dsl_state, sign_count_field, :integer, allow_nil?: false),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, user_handle_field, :binary,
             allow_nil?: true,
             writable?: true,
             public?: true
           ),
         :ok <- validate_attribute(dsl_state, user_handle_field, :binary, allow_nil?: true),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, transports_field, {:array, :string},
             allow_nil?: true,
             writable?: true,
             public?: true
           ),
         :ok <-
           validate_attribute(dsl_state, transports_field, {:array, :string}, allow_nil?: true),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, backup_eligible_field, :boolean,
             allow_nil?: true,
             writable?: true,
             public?: true
           ),
         :ok <- validate_attribute(dsl_state, backup_eligible_field, :boolean, allow_nil?: true),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, backed_up_field, :boolean,
             allow_nil?: true,
             writable?: true,
             public?: true
           ),
         :ok <- validate_attribute(dsl_state, backed_up_field, :boolean, allow_nil?: true),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, discoverable_field, :boolean,
             allow_nil?: true,
             writable?: true,
             public?: true
           ),
         :ok <- validate_attribute(dsl_state, discoverable_field, :boolean, allow_nil?: true),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, label_field, :string,
             default: "Security Key",
             writable?: true,
             public?: true
           ),
         :ok <- validate_attribute(dsl_state, label_field, :string, allow_nil?: true),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, last_used_at_field, :utc_datetime_usec,
             allow_nil?: true,
             writable?: true,
             public?: true
           ),
         :ok <-
           validate_attribute(dsl_state, last_used_at_field, :utc_datetime_usec, allow_nil?: true),
         {:ok, read_action_name} <- Info.webauthn_credential_read_action_name(dsl_state),
         {:ok, destroy_action_name} <- Info.webauthn_credential_destroy_action_name(dsl_state),
         {:ok, create_action_name} <- Info.webauthn_credential_create_action_name(dsl_state),
         {:ok, update_action_name} <- Info.webauthn_credential_update_action_name(dsl_state),
         {:ok, dsl_state} <- maybe_build_primary_key(dsl_state),
         {:ok, dsl_state} <- maybe_build_unique_identity(dsl_state, credential_id_field),
         :ok <- validate_unique_identity(dsl_state, credential_id_field),
         {:ok, dsl_state} <-
           maybe_build_action(dsl_state, read_action_name, fn _ ->
             Transformer.build_entity(Resource.Dsl, [:actions], :read,
               name: read_action_name,
               primary?: true
             )
           end),
         {:ok, dsl_state} <-
           maybe_build_action(dsl_state, destroy_action_name, fn _ ->
             Transformer.build_entity(Resource.Dsl, [:actions], :destroy,
               name: destroy_action_name,
               primary?: true
             )
           end),
         {:ok, dsl_state} <-
           maybe_build_action(dsl_state, create_action_name, fn _ ->
             Transformer.build_entity(Resource.Dsl, [:actions], :create,
               name: create_action_name,
               primary?: true,
               accept: [
                 credential_id_field,
                 public_key_field,
                 sign_count_field,
                 user_handle_field,
                 transports_field,
                 backup_eligible_field,
                 backed_up_field,
                 discoverable_field,
                 label_field,
                 user_id_field
               ]
             )
           end) do
      maybe_build_action(dsl_state, update_action_name, fn _ ->
        Transformer.build_entity(Resource.Dsl, [:actions], :update,
          name: update_action_name,
          primary?: true,
          accept: [sign_count_field, label_field, last_used_at_field, backed_up_field]
        )
      end)
    end
  end

  # `user_id_field` defaults to `nil` so the belongs_to relationship's own
  # `<name>_id` convention can apply. Once the relationship is built, its
  # `source_attribute` holds whatever was actually resolved (either that
  # convention or an explicit `user_id_field` override) — read it back here
  # so the create action's `accept` list below uses the real attribute name
  # instead of the pre-resolution `nil`.
  defp resolve_user_id_field(_dsl_state, _relationship_name, user_id_field)
       when not is_nil(user_id_field),
       do: user_id_field

  defp resolve_user_id_field(dsl_state, relationship_name, nil) do
    %{source_attribute: source_attribute} =
      Resource.Info.relationship(dsl_state, relationship_name)

    source_attribute
  end

  defp build_user_relationship(_dsl_state, name, destination, user_id_field) do
    with {:ok, id_attr} <- find_pk(destination) do
      Transformer.build_entity(Resource.Dsl, [:relationships], :belongs_to,
        name: name,
        destination: destination,
        destination_attribute: id_attr.name,
        attribute_type: id_attr.type,
        source_attribute: user_id_field,
        allow_nil?: false,
        public?: true
      )
    end
  end

  defp find_pk(resource) do
    case Resource.Info.primary_key(resource) do
      [id_field] -> {:ok, Resource.Info.attribute(resource, id_field)}
      _ -> {:error, "`#{inspect(resource)}` must have a single-attribute primary key."}
    end
  end

  defp maybe_build_primary_key(dsl_state) do
    has_primary_key? =
      dsl_state
      |> Transformer.get_entities([:attributes])
      |> Enum.any?(& &1.primary_key?)

    if has_primary_key? do
      {:ok, dsl_state}
    else
      {:ok, attr} =
        Transformer.build_entity(Resource.Dsl, [:attributes], :uuid_primary_key, name: :id)

      {:ok, Transformer.add_entity(dsl_state, [:attributes], attr)}
    end
  end

  defp maybe_build_unique_identity(dsl_state, credential_id_field) do
    identity_name = :unique_credential_id

    existing =
      dsl_state
      |> Transformer.get_entities([:identities])
      |> Enum.find(&(&1.name == identity_name))

    if existing do
      {:ok, dsl_state}
    else
      {:ok, identity} =
        Transformer.build_entity(Resource.Dsl, [:identities], :identity,
          name: identity_name,
          keys: [credential_id_field]
        )

      {:ok, Transformer.add_entity(dsl_state, [:identities], identity)}
    end
  end

  defp validate_wax_dependency do
    if Code.ensure_loaded?(Wax) do
      :ok
    else
      {:error,
       DslError.exception(
         path: [:webauthn_credential],
         message: """
         The WebAuthn credential extension requires the optional `:wax_` dependency.

         Add it to your dependencies:

             {:wax_, "~> 0.7"}
         """
       )}
    end
  end

  defp validate_attribute(dsl_state, field, expected_type, opts) do
    resource = Transformer.get_persisted(dsl_state, :module)

    case find_attribute(dsl_state, field) do
      {:ok, attribute} ->
        actual_type = Ash.Type.get_type(attribute.type)
        expected_type = Ash.Type.get_type(expected_type)

        cond do
          actual_type != expected_type ->
            {:error,
             DslError.exception(
               path: [:webauthn_credential],
               message:
                 "The `#{inspect(field)}` attribute on `#{inspect(resource)}` must have type " <>
                   "`#{inspect(expected_type)}` (found `#{inspect(actual_type)}`)."
             )}

          opts[:allow_nil?] == false && attribute.allow_nil? ->
            {:error,
             DslError.exception(
               path: [:webauthn_credential],
               message:
                 "The `#{inspect(field)}` attribute on `#{inspect(resource)}` must be `allow_nil? false`."
             )}

          true ->
            :ok
        end

      _ ->
        {:error,
         DslError.exception(
           path: [:webauthn_credential],
           message:
             "The resource `#{inspect(resource)}` is missing the `#{inspect(field)}` attribute."
         )}
    end
  end

  defp validate_user_relationship(dsl_state, relationship_name, user_resource) do
    resource = Transformer.get_persisted(dsl_state, :module)

    case Resource.Info.relationship(dsl_state, relationship_name) do
      %{type: :belongs_to, destination: ^user_resource} ->
        :ok

      %{type: :belongs_to, destination: other} ->
        {:error,
         DslError.exception(
           path: [:webauthn_credential],
           message:
             "The `#{inspect(relationship_name)}` relationship points to `#{inspect(other)}` " <>
               "but `user_resource` is configured as `#{inspect(user_resource)}`."
         )}

      %{type: type} ->
        {:error,
         DslError.exception(
           path: [:webauthn_credential],
           message:
             "The `#{inspect(relationship_name)}` relationship on `#{inspect(resource)}` must " <>
               "be a `belongs_to` (found `#{type}`)."
         )}
    end
  end

  defp validate_unique_identity(dsl_state, credential_id_field) do
    resource = Transformer.get_persisted(dsl_state, :module)

    case Resource.Info.identity(dsl_state, :unique_credential_id) do
      %{keys: keys} ->
        if credential_id_field in keys do
          :ok
        else
          {:error,
           DslError.exception(
             path: [:webauthn_credential],
             message:
               "The `unique_credential_id` identity on `#{inspect(resource)}` must include " <>
                 "`#{inspect(credential_id_field)}`."
           )}
        end

      nil ->
        {:error,
         DslError.exception(
           path: [:webauthn_credential],
           message:
             "The `#{inspect(resource)}` resource must define a `unique_credential_id` identity " <>
               "covering `#{inspect(credential_id_field)}`."
         )}
    end
  end
end
