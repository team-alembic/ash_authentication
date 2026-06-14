# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.WebAuthnCredential.Verifier do
  @moduledoc """
  DSL verifier for the `AshAuthentication.WebAuthnCredential` extension.

  Validates at compile time that the credential resource has the correct
  attribute types, a valid `belongs_to` relationship to the user resource,
  and a unique identity on `credential_id`.
  """

  use Spark.Dsl.Verifier

  import AshAuthentication.Validations

  alias Ash.Resource.Info, as: ResourceInfo
  alias AshAuthentication.Strategy.WebAuthn.CoseKey
  alias AshAuthentication.WebAuthnCredential.Info
  alias Spark.Dsl.Verifier, as: DslVerifier
  alias Spark.Error.DslError

  @doc false
  @impl Spark.Dsl.Verifier
  def verify(dsl_state) do
    with :ok <- verify_wax_dependency(),
         {:ok, credential_id_field} <- Info.webauthn_credential_credential_id_field(dsl_state),
         {:ok, public_key_field} <- Info.webauthn_credential_public_key_field(dsl_state),
         {:ok, sign_count_field} <- Info.webauthn_credential_sign_count_field(dsl_state),
         {:ok, user_resource} <- Info.webauthn_credential_user_resource(dsl_state),
         {:ok, user_relationship_name} <-
           Info.webauthn_credential_user_relationship_name(dsl_state),
         :ok <- verify_attribute(dsl_state, credential_id_field, :binary, allow_nil?: false),
         :ok <- verify_attribute(dsl_state, public_key_field, CoseKey, allow_nil?: false),
         :ok <- verify_attribute(dsl_state, sign_count_field, :integer, allow_nil?: false),
         :ok <- verify_user_relationship(dsl_state, user_relationship_name, user_resource) do
      verify_unique_identity(dsl_state, credential_id_field)
    end
  end

  defp verify_wax_dependency do
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

  defp verify_attribute(dsl_state, field, expected_type, opts) do
    resource = DslVerifier.get_persisted(dsl_state, :module)

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

  defp verify_user_relationship(dsl_state, relationship_name, user_resource) do
    resource = DslVerifier.get_persisted(dsl_state, :module)

    case ResourceInfo.relationship(dsl_state, relationship_name) do
      nil ->
        {:error,
         DslError.exception(
           path: [:webauthn_credential],
           message: """
           The resource `#{inspect(resource)}` is missing the \
           `#{inspect(relationship_name)}` relationship.

           Add a `belongs_to` pointing to `#{inspect(user_resource)}`:

               relationships do
                 belongs_to :#{relationship_name}, #{inspect(user_resource)}, allow_nil?: false
               end
           """
         )}

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
             "The `#{inspect(relationship_name)}` relationship must be a `belongs_to` " <>
               "(found `#{type}`)."
         )}
    end
  end

  defp verify_unique_identity(dsl_state, credential_id_field) do
    resource = DslVerifier.get_persisted(dsl_state, :module)

    case ResourceInfo.identity(dsl_state, :unique_credential_id) do
      nil ->
        {:error,
         DslError.exception(
           path: [:webauthn_credential],
           message: """
           The resource `#{inspect(resource)}` is missing a \
           `unique_credential_id` identity on `#{inspect(credential_id_field)}`.

               identities do
                 identity :unique_credential_id, [#{inspect(credential_id_field)}]
               end
           """
         )}

      %{keys: keys} ->
        if credential_id_field in keys do
          :ok
        else
          {:error,
           DslError.exception(
             path: [:webauthn_credential],
             message:
               "The `unique_credential_id` identity must include `#{inspect(credential_id_field)}`."
           )}
        end
    end
  end
end
