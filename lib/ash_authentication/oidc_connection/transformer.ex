# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.OidcConnection.Transformer do
  @moduledoc """
  Sets up default attributes and actions for resources extended with
  `AshAuthentication.OidcConnection`.

  For each configured field (`base_url_field`, `client_id_field`, etc.), if
  the resource doesn't already define it (as an attribute, calculation,
  aggregate, or relationship), a default string attribute is built. Users
  can replace any field with a calculation (e.g. one that decrypts an
  encrypted column on load) by simply defining it on the resource.
  """

  use Spark.Dsl.Transformer
  alias Ash.{Resource, Type}
  alias AshAuthentication.OidcConnection
  alias Spark.Dsl.Transformer
  import AshAuthentication.Utils

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
  def before?(_), do: false

  @doc false
  @impl true
  @spec transform(map) ::
          :ok | {:ok, map} | {:error, term} | {:warn, map, String.t() | [String.t()]} | :halt
  def transform(dsl_state) do
    with {:ok, dsl_state} <- maybe_set_domain(dsl_state, :oidc_connection),
         {:ok, id_attribute} <- OidcConnection.Info.oidc_connection_id_attribute_name(dsl_state),
         {:ok, dsl_state} <-
           maybe_build_attribute(dsl_state, id_attribute, Type.UUID,
             allow_nil?: false,
             writable?: true,
             primary_key?: true,
             default: &Ash.UUID.generate/0
           ),
         {:ok, dsl_state} <-
           maybe_build_field(dsl_state, :base_url_field, Type.String,
             allow_nil?: false,
             writable?: true,
             public?: true
           ),
         {:ok, dsl_state} <-
           maybe_build_field(dsl_state, :client_id_field, Type.String,
             allow_nil?: false,
             writable?: true,
             public?: true
           ),
         {:ok, dsl_state} <-
           maybe_build_field(dsl_state, :client_secret_field, Type.String,
             allow_nil?: false,
             writable?: true,
             sensitive?: true
           ),
         {:ok, dsl_state} <-
           maybe_build_field(dsl_state, :display_name_field, Type.String,
             allow_nil?: true,
             writable?: true,
             public?: true
           ),
         {:ok, dsl_state} <-
           maybe_build_field(dsl_state, :icon_url_field, Type.String,
             allow_nil?: true,
             writable?: true,
             public?: true
           ),
         {:ok, read_action_name} <-
           OidcConnection.Info.oidc_connection_read_action_name(dsl_state) do
      maybe_build_action(dsl_state, read_action_name, fn _ ->
        build_read_action(read_action_name)
      end)
    end
  end

  # If the resource doesn't already define a field with the configured name
  # (whether as an attribute, calculation, aggregate, or relationship),
  # build the default string attribute for it. Users can replace the
  # auto-built attribute by defining one of those themselves — e.g. a
  # calculation that decrypts an encrypted column on load.
  # sobelow_skip ["DOS.BinToAtom"]
  defp maybe_build_field(dsl_state, dsl_key, type, opts) do
    {:ok, field_name} = apply(OidcConnection.Info, :"oidc_connection_#{dsl_key}", [dsl_state])

    cond do
      is_nil(field_name) -> {:ok, dsl_state}
      Ash.Resource.Info.field(dsl_state, field_name) -> {:ok, dsl_state}
      true -> maybe_build_attribute(dsl_state, field_name, type, opts)
    end
  end

  defp build_read_action(action_name) do
    Transformer.build_entity(Resource.Dsl, [:actions], :read,
      name: action_name,
      primary?: true
    )
  end
end
