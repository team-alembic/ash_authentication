# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Verifier do
  @moduledoc """
  DSL verifier for the WebAuthn strategy.

  Validates configuration at compile time.
  """

  alias Ash.Resource.Info, as: ResourceInfo
  alias AshAuthentication.Strategy.CustomFields
  alias AshAuthentication.Strategy.WebAuthn
  alias Spark.Error.DslError

  @doc false
  @spec verify(WebAuthn.t(), map) :: :ok | {:error, Exception.t()}
  def verify(strategy, dsl_state) do
    with :ok <- validate_wax_dependency(),
         :ok <- validate_rp_id(strategy),
         :ok <- validate_credential_resource(strategy),
         :ok <- validate_credential_resource_shape(strategy, dsl_state),
         :ok <- validate_tokens_enabled(dsl_state),
         :ok <- validate_verify_action(strategy, dsl_state),
         :ok <- validate_register_action_manages_credential(strategy, dsl_state),
         :ok <- CustomFields.verify_secret_confirmations(strategy, dsl_state) do
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

  # The credential resource is declared in `no_depend_modules`, so it may not
  # be compiled when the user resource is verified. Skip the checks that need
  # to introspect it if it isn't loaded yet.
  #
  # Nothing is lost by deferring: the credential resource's own transformer
  # validates its attributes, relationship and identity as it compiles, and
  # every value the strategy reads back off it now comes from that same DSL
  # rather than from a second copy on this side.
  defp validate_credential_resource_shape(strategy, dsl_state) do
    if Code.ensure_loaded?(strategy.credential_resource) and
         function_exported?(strategy.credential_resource, :spark_dsl_config, 0) do
      with :ok <- validate_credential_resource_extension(strategy) do
        validate_credentials_relationship_destination(strategy, dsl_state)
      end
    else
      :ok
    end
  end

  # As of 5.0 the credential resource must use the `WebAuthnCredential`
  # extension — the strategy reads every credential field name, the
  # belongs-to name and the credential action names straight off its DSL, so
  # a resource without it has nothing to read and would silently fall back to
  # this extension's defaults.
  defp validate_credential_resource_extension(strategy) do
    if AshAuthentication.WebAuthnCredential in Spark.extensions(strategy.credential_resource) do
      :ok
    else
      {:error,
       DslError.exception(
         path: [:authentication, :strategies, strategy.name, :credential_resource],
         message: """
         The credential resource `#{inspect(strategy.credential_resource)}` must use the \
         `AshAuthentication.WebAuthnCredential` extension.

         Add it to the resource:

             use Ash.Resource,
               extensions: [AshAuthentication.WebAuthnCredential]

             webauthn_credential do
               user_resource #{inspect(strategy.resource)}
             end

         The extension builds and validates the credential's attributes, its \
         `belongs_to` to the user resource, and its actions — and is where all \
         of their names are configured.
         """
       )}
    end
  end

  # The `has_many` on the user resource and the `belongs_to` on the credential
  # resource must meet on the same column. The strategy's transformer can only
  # guess the former (the credential resource isn't compiled when it runs), so
  # confirm the guess here, where it is.
  defp validate_credentials_relationship_destination(strategy, dsl_state) do
    with %{destination_attribute: destination_attribute} <-
           ResourceInfo.relationship(dsl_state, strategy.credentials_relationship_name),
         %{source_attribute: source_attribute} <-
           ResourceInfo.relationship(
             strategy.credential_resource,
             WebAuthn.user_relationship_name(strategy)
           ),
         false <- destination_attribute == source_attribute do
      {:error,
       DslError.exception(
         path: [:authentication, :strategies, strategy.name, :credentials_relationship_name],
         message: """
         The `#{inspect(strategy.credentials_relationship_name)}` relationship on \
         `#{inspect(strategy.resource)}` points at `#{inspect(destination_attribute)}` on \
         `#{inspect(strategy.credential_resource)}`, but that resource's \
         `#{inspect(WebAuthn.user_relationship_name(strategy))}` relationship uses \
         `#{inspect(source_attribute)}`.

         The generated `has_many` derives its foreign key from this resource's name, which \
         only matches when the credential resource's `belongs_to` is named after it too. \
         Declare the relationship yourself to say which column to use:

             relationships do
               has_many #{inspect(strategy.credentials_relationship_name)}, \
         #{inspect(strategy.credential_resource)} do
                 destination_attribute #{inspect(source_attribute)}
               end
             end
         """
       )}
    else
      _ -> :ok
    end
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

  defp validate_register_action_manages_credential(%{registration_enabled?: false}, _dsl_state),
    do: :ok

  defp validate_register_action_manages_credential(strategy, dsl_state) do
    case Ash.Resource.Info.action(dsl_state, strategy.register_action_name) do
      nil ->
        {:error,
         DslError.exception(
           path: [:authentication, :strategies, strategy.name],
           message: """
           The WebAuthn strategy expects a `#{inspect(strategy.register_action_name)}` create \
           action on `#{inspect(strategy.resource)}` (auto-generated by the strategy's \
           transformer when `registration_enabled? true`). It looks like the action is missing.
           """
         )}

      action ->
        if manages_credentials_relationship?(action, strategy.credentials_relationship_name) do
          :ok
        else
          {:error,
           DslError.exception(
             path: [:authentication, :strategies, strategy.name],
             message: """
             The `#{inspect(strategy.register_action_name)}` action on \
             `#{inspect(strategy.resource)}` does not manage the \
             `#{inspect(strategy.credentials_relationship_name)}` relationship.

             Without this, the WebAuthn credential would be created outside of the user's \
             changeset/transaction, risking an orphaned user if credential creation fails.

             Add the following to the action:

                 change manage_relationship(:#{strategy.credentials_relationship_name}, type: :direct_control)
             """
           )}
        end
    end
  end

  @doc false
  def manages_credentials_relationship?(action, relationship_name) do
    Enum.any?(action.changes, fn
      %{change: {Ash.Resource.Change.ManageRelationship, opts}} ->
        opts[:relationship] == relationship_name

      _ ->
        false
    end)
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
