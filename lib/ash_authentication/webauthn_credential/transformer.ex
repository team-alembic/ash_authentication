# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.WebAuthnCredential.Transformer do
  @moduledoc """
  DSL transformer for the `AshAuthentication.WebAuthnCredential` extension.

  Automatically scaffolds the required attributes, `belongs_to` relationship,
  and unique identity on the credential resource so users don't have to
  define them manually.
  """

  use Spark.Dsl.Transformer

  import AshAuthentication.Utils

  alias Ash.Resource
  alias Spark.Dsl.Transformer

  alias AshAuthentication.Strategy.WebAuthn.CoseKey
  alias AshAuthentication.WebAuthnCredential.Info

  @doc false
  @impl Transformer
  def after?(_), do: false

  @doc false
  @impl Transformer
  def transform(dsl_state) do
    with {:ok, credential_id_field} <- Info.webauthn_credential_credential_id_field(dsl_state),
         {:ok, public_key_field} <- Info.webauthn_credential_public_key_field(dsl_state),
         {:ok, sign_count_field} <- Info.webauthn_credential_sign_count_field(dsl_state),
         {:ok, label_field} <- Info.webauthn_credential_label_field(dsl_state),
         {:ok, last_used_at_field} <- Info.webauthn_credential_last_used_at_field(dsl_state),
         {:ok, user_id_field} <- Info.webauthn_credential_user_id_field(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, credential_id_field, :binary,
             allow_nil?: false,
             writable?: true,
             public?: true
           ),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, public_key_field, CoseKey,
             allow_nil?: false,
             writable?: true,
             public?: true
           ),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, sign_count_field, :integer,
             allow_nil?: false,
             default: 0,
             writable?: true,
             public?: true
           ),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, label_field, :string,
             default: "Security Key",
             writable?: true,
             public?: true
           ),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, last_used_at_field, :utc_datetime_usec,
             allow_nil?: true,
             writable?: true,
             public?: true
           ),
         {:ok, read_action_name} <- Info.webauthn_credential_read_action_name(dsl_state),
         {:ok, destroy_action_name} <- Info.webauthn_credential_destroy_action_name(dsl_state),
         {:ok, create_action_name} <- Info.webauthn_credential_create_action_name(dsl_state),
         {:ok, update_action_name} <- Info.webauthn_credential_update_action_name(dsl_state),
         {:ok, dsl_state} <- maybe_build_primary_key(dsl_state),
         {:ok, dsl_state} <- maybe_build_unique_identity(dsl_state, credential_id_field),
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
                 label_field,
                 user_id_field
               ]
             )
           end) do
      maybe_build_action(dsl_state, update_action_name, fn _ ->
        Transformer.build_entity(Resource.Dsl, [:actions], :update,
          name: update_action_name,
          primary?: true,
          accept: [sign_count_field, label_field, last_used_at_field]
        )
      end)
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
end
