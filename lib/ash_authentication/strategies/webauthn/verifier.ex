# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Verifier do
  @moduledoc """
  DSL verifier for the WebAuthn strategy.

  Validates configuration at compile time.
  """

  alias Ash.Resource.Info, as: ResourceInfo
  alias AshAuthentication.Strategy.WebAuthn
  alias Spark.Error.DslError

  @doc false
  @spec verify(WebAuthn.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl_state) do
    with :ok <- validate_wax_dependency(),
         :ok <- validate_rp_id(strategy),
         :ok <- validate_credential_resource(strategy),
         :ok <- validate_credentials_relationship(strategy, dsl_state),
         :ok <- validate_credential_resource_shape(strategy),
         :ok <- validate_tokens_enabled(dsl_state),
         :ok <- validate_verify_action(strategy, dsl_state) do
      validate_hashed_password_optional(strategy, dsl_state)
    end
  end

  defp validate_wax_dependency do
    if Code.ensure_loaded?(Wax) do
      :ok
    else
      {:error,
       DslError.exception(
         path: [:authentication, :strategies, :webauthn],
         message: """
         The WebAuthn strategy requires the optional `:wax_` dependency.

         Add it to your dependencies:

             {:wax_, "~> 0.7"}

         If `ash_authentication` was already compiled without `:wax_`, recompile it:

             mix deps.compile ash_authentication --force
         """
       )}
    end
  end

  defp validate_rp_id(%{rp_id: rp_id}) when is_binary(rp_id) do
    cond do
      String.starts_with?(rp_id, "http://") or String.starts_with?(rp_id, "https://") ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, :webauthn],
           message:
             "rp_id must be a domain name without protocol prefix (e.g. \"example.com\", not \"https://example.com\")"
         )}

      String.contains?(rp_id, "/") ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, :webauthn],
           message:
             "rp_id must be a domain name without paths (e.g. \"example.com\", not \"example.com/auth\")"
         )}

      true ->
        :ok
    end
  end

  defp validate_rp_id(_), do: :ok

  defp validate_credential_resource(%{credential_resource: nil}) do
    {:error,
     DslError.exception(
       path: [:authentication, :strategies, :webauthn],
       message: "credential_resource is required"
     )}
  end

  defp validate_credential_resource(_), do: :ok

  defp validate_credentials_relationship(strategy, dsl_state) do
    case ResourceInfo.relationship(dsl_state, strategy.credentials_relationship_name) do
      nil ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, strategy.name],
           message: """
           The user resource is missing the `#{inspect(strategy.credentials_relationship_name)}` relationship.

           Add a `has_many` relationship to the credential resource:

               relationships do
                 has_many :#{strategy.credentials_relationship_name}, #{inspect(strategy.credential_resource)}
               end
           """
         )}

      %{type: :has_many, destination: destination}
      when destination == strategy.credential_resource ->
        :ok

      %{type: type} ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, strategy.name],
           message:
             "The `#{inspect(strategy.credentials_relationship_name)}` relationship must be a `has_many` to `#{inspect(strategy.credential_resource)}` (found `#{type}`)."
         )}
    end
  end

  # The credential resource may be in `no_depend_modules`, so it may not be
  # compiled when the user resource is verified. Skip shape checks if we
  # can't introspect it yet — they will run when the credential resource
  # is itself compiled.
  defp validate_credential_resource_shape(strategy) do
    if Code.ensure_loaded?(strategy.credential_resource) and
         function_exported?(strategy.credential_resource, :spark_dsl_config, 0) do
      with :ok <- validate_belongs_to_user(strategy),
           :ok <- validate_required_attribute(strategy, strategy.credential_id_field, :binary),
           :ok <-
             validate_required_attribute(
               strategy,
               strategy.public_key_field,
               WebAuthn.CoseKey
             ) do
        validate_required_attribute(strategy, strategy.sign_count_field, :integer)
      end
    else
      :ok
    end
  end

  defp validate_belongs_to_user(strategy) do
    case ResourceInfo.relationship(strategy.credential_resource, strategy.user_relationship_name) do
      %{type: :belongs_to} ->
        :ok

      nil ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, strategy.name],
           message: """
           The credential resource `#{inspect(strategy.credential_resource)}` is missing the \
           `#{inspect(strategy.user_relationship_name)}` relationship.

           Add a `belongs_to` relationship pointing to the user resource:

               relationships do
                 belongs_to :#{strategy.user_relationship_name}, MyApp.Accounts.User, allow_nil?: false
               end
           """
         )}

      %{type: type} ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, strategy.name],
           message:
             "The `#{inspect(strategy.user_relationship_name)}` relationship on `#{inspect(strategy.credential_resource)}` must be a `belongs_to` (found `#{type}`)."
         )}
    end
  end

  defp validate_required_attribute(strategy, name, expected_type) do
    case ResourceInfo.attribute(strategy.credential_resource, name) do
      nil ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, strategy.name],
           message:
             "The credential resource `#{inspect(strategy.credential_resource)}` is missing the `#{inspect(name)}` attribute."
         )}

      %{type: type} ->
        if attribute_type_matches?(type, expected_type) do
          :ok
        else
          {:error,
           DslError.exception(
             path: [:authentication, :strategies, strategy.name],
             message:
               "The `#{inspect(name)}` attribute on `#{inspect(strategy.credential_resource)}` must have type `#{inspect(expected_type)}` (found `#{inspect(type)}`)."
           )}
        end
    end
  end

  defp attribute_type_matches?(actual, expected) do
    Ash.Type.get_type(actual) == Ash.Type.get_type(expected)
  end

  defp validate_tokens_enabled(dsl_state) do
    if AshAuthentication.Info.authentication_tokens_enabled?(dsl_state) do
      :ok
    else
      {:error,
       DslError.exception(
         path: [:authentication, :strategies, :webauthn],
         message: """
         The WebAuthn strategy requires tokens to be enabled.

         Add the following to your authentication block:

             authentication do
               tokens do
                 enabled? true
                 token_resource YourApp.Accounts.Token
                 signing_secret YourApp.Secrets
               end
             end
         """
       )}
    end
  end

  defp validate_verify_action(%{verify_enabled?: false}, _dsl_state), do: :ok

  defp validate_verify_action(strategy, dsl_state) do
    case Ash.Resource.Info.action(dsl_state, strategy.verify_action_name) do
      nil ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, strategy.name],
           message: """
           The WebAuthn strategy expects a `#{inspect(strategy.verify_action_name)}` read \
           action on `#{inspect(strategy.resource)}` (auto-generated by the strategy's \
           transformer when `verify_enabled? true`). It looks like the action is missing.
           """
         )}

      _action ->
        :ok
    end
  end

  # WebAuthn registration creates a user without a password, so when the
  # password strategy also exists on the same resource, `hashed_password` must
  # be nil-able. Surface the conflict at compile time instead of at the first
  # registration attempt.
  defp validate_hashed_password_optional(strategy, dsl_state) do
    with true <- strategy.registration_enabled?,
         true <- AshAuthentication.Info.strategy_enabled?(dsl_state, :password),
         %{allow_nil?: false} <- ResourceInfo.attribute(dsl_state, :hashed_password) do
      {:error,
       DslError.exception(
         path: [:authentication, :strategies, strategy.name],
         message: """
         The `:hashed_password` attribute is `allow_nil? false`, but the WebAuthn
         strategy registers users without a password. Both strategies can coexist
         on the same resource only if `:hashed_password` is nil-able.

         Update the attribute on `#{inspect(strategy.resource)}`:

             attribute :hashed_password, :string do
               sensitive? true
             end

         (i.e. drop the `allow_nil? false` line — the default is `true`.)
         """
       )}
    else
      _ -> :ok
    end
  end
end
