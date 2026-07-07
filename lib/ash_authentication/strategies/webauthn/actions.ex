# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Actions do
  @moduledoc """
  Core action implementations for the WebAuthn strategy.

  Wraps the `wax_` library for FIDO2 ceremony handling and coordinates
  with Ash to persist users and credentials.
  """

  alias AshAuthentication.Errors.AuthenticationFailed

  if Code.ensure_loaded?(Wax) do
    alias Ash.{Changeset, Query}
    alias AshAuthentication.{Info, Jwt, Strategy.WebAuthn}
    import Ash.Expr, only: [ref: 1]
    require Ash.Query
    require Logger

    @doc """
    Generate a registration challenge.

    Pass `origin: "..."` in `opts` to override the strategy's configured origin
    (e.g. with the request's actual origin when serving from a Plug or
    LiveView).
    """
    @spec registration_challenge(WebAuthn.t(), any, keyword) :: {:ok, Wax.Challenge.t()}
    def registration_challenge(strategy, tenant, opts \\ []) do
      wax_opts = WebAuthn.Helpers.wax_opts(strategy, tenant, opts)
      challenge = Wax.new_registration_challenge(wax_opts)
      {:ok, challenge}
    end

    @doc """
    Generate an authentication challenge.

    Pass `origin: "..."` in `opts` to override the strategy's configured origin.
    """
    @spec authentication_challenge(WebAuthn.t(), list, any, keyword) ::
            {:ok, Wax.Challenge.t()}
    def authentication_challenge(strategy, allow_credentials, tenant, opts \\ []) do
      wax_opts =
        strategy
        |> WebAuthn.Helpers.wax_opts(tenant, opts)
        |> Keyword.put(:allow_credentials, allow_credentials)

      challenge = Wax.new_authentication_challenge(wax_opts)
      {:ok, challenge}
    end

    @doc "Register a new user with a WebAuthn credential."
    @spec register(WebAuthn.t(), map, keyword) :: {:ok, Ash.Resource.Record.t()} | {:error, any}
    def register(strategy, params, opts \\ []) do
      challenge = Keyword.fetch!(opts, :challenge)

      with {:ok, attestation_object} <- safe_url_decode64(params["attestation_object"]),
           {:ok, client_data_json} <- safe_url_decode64(params["client_data_json"]),
           {:ok, {auth_data, _}} <-
             wax_register(strategy, attestation_object, client_data_json, challenge),
           {:ok, user} <- create_user_from_registration(strategy, auth_data, params, opts) do
        case store_credential_from_auth(strategy, user, auth_data, params, opts) do
          {:ok, _credential} ->
            {:ok, user}

          {:error, error} ->
            cleanup_orphaned_user(user, opts)
            {:error, error}
        end
      else
        :error -> base64_error(strategy, :register)
        {:error, error} -> {:error, error}
      end
    end

    # Compensating cleanup: if credential store fails after user creation, destroy
    # the user to prevent orphans. Failure to clean up is logged loudly but does
    # not mask the original error.
    defp cleanup_orphaned_user(user, opts) do
      ash_opts = internal_ash_opts(Keyword.get(opts, :tenant))

      user
      |> Changeset.new()
      |> Changeset.set_context(auth_context())
      |> Ash.destroy(ash_opts)
      |> case do
        :ok ->
          :ok

        {:ok, _} ->
          :ok

        {:error, error} ->
          Logger.error(
            "Failed to clean up orphaned user after WebAuthn credential store failure: " <>
              inspect(error)
          )

          :error
      end
    end

    @doc """
    Sign in a user using a short-lived sign-in token issued by a successful
    WebAuthn ceremony.

    The token is verified, the matching user is loaded, and a fresh
    authentication token is placed in `user.__metadata__.token` for use as a
    session credential.
    """
    @spec sign_in_with_token(WebAuthn.t(), map, keyword) ::
            {:ok, Ash.Resource.Record.t()} | {:error, any}
    def sign_in_with_token(strategy, params, opts \\ []) do
      opts =
        opts
        |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)
        |> Keyword.put_new(:skip_unknown_inputs, [:*])

      strategy.resource
      |> Query.new()
      |> Query.set_context(%{private: %{ash_authentication?: true}})
      |> Query.for_read(strategy.sign_in_with_token_action_name, params, opts)
      |> Ash.read()
      |> case do
        {:ok, [user]} ->
          {:ok, user}

        {:error, error} when is_struct(error, AuthenticationFailed) ->
          {:error, error}

        {:error, error} when is_exception(error) ->
          {:error,
           AuthenticationFailed.exception(
             strategy: strategy,
             caused_by: %{
               module: __MODULE__,
               strategy: strategy,
               action: strategy.sign_in_with_token_action_name,
               message: Exception.message(error)
             }
           )}

        {:error, reason} ->
          {:error,
           AuthenticationFailed.exception(
             strategy: strategy,
             caused_by: %{
               module: __MODULE__,
               strategy: strategy,
               action: strategy.sign_in_with_token_action_name,
               message: reason
             }
           )}
      end
    end

    @doc "Sign in a user with a WebAuthn credential."
    @spec sign_in(WebAuthn.t(), map, keyword) :: {:ok, Ash.Resource.Record.t()} | {:error, any}
    def sign_in(strategy, params, opts \\ []) do
      challenge = Keyword.fetch!(opts, :challenge)
      tenant = Keyword.get(opts, :tenant)

      with {:ok, _credential, user} <-
             run_assertion_ceremony(
               strategy,
               :sign_in,
               params,
               challenge,
               tenant,
               &lookup_credential_and_user(strategy, &1, tenant)
             ),
           :ok <- verify_identity_matches(strategy, :sign_in, params, user) do
        maybe_generate_token(user, strategy, opts)
      end
    end

    @doc """
    Verify that the caller can produce a valid WebAuthn assertion using one of
    `actor`'s registered credentials.

    Used as a second factor on top of another primary credential. On success,
    stamps `:webauthn_verified_at` onto the user metadata and (if tokens are
    enabled) issues a fresh JWT carrying the same value as a `webauthn_verified_at`
    claim — both are picked up by `RequireWebauthn` on subsequent requests.
    """
    @spec verify(WebAuthn.t(), map, keyword) :: {:ok, Ash.Resource.Record.t()} | {:error, any}
    def verify(strategy, params, opts \\ []) do
      actor = Keyword.fetch!(opts, :actor)
      challenge = Keyword.fetch!(opts, :challenge)
      tenant = Keyword.get(opts, :tenant)

      with {:ok, _credential, _user} <-
             run_assertion_ceremony(
               strategy,
               :verify,
               params,
               challenge,
               tenant,
               &lookup_credential_for_actor(strategy, &1, actor, tenant)
             ) do
        verified_at = DateTime.utc_now()
        actor = Ash.Resource.put_metadata(actor, :webauthn_verified_at, verified_at)
        maybe_generate_verified_token(actor, strategy, opts, verified_at)
      end
    end

    # Decode the assertion params, look up the credential via the supplied
    # `lookup_fn`, ask Wax to verify the signature, and best-effort update the
    # sign count. Returns `{:ok, credential, user}` so callers can proceed
    # with their action-specific work.
    defp run_assertion_ceremony(strategy, action_name, params, challenge, tenant, lookup_fn) do
      with {:ok, raw_id} <- safe_url_decode64(params["raw_id"]),
           {:ok, authenticator_data} <- safe_url_decode64(params["authenticator_data"]),
           {:ok, signature} <- safe_url_decode64(params["signature"]),
           {:ok, client_data_json} <- safe_url_decode64(params["client_data_json"]),
           {:ok, credential, user} <- lookup_fn.(raw_id),
           {:ok, auth_data} <-
             wax_authenticate(
               strategy,
               action_name,
               raw_id,
               authenticator_data,
               signature,
               client_data_json,
               challenge,
               [{raw_id, Map.get(credential, strategy.public_key_field)}]
             ),
           :ok <- best_effort_update_sign_count(strategy, raw_id, auth_data.sign_count, tenant) do
        {:ok, credential, user}
      else
        :error -> base64_error(strategy, action_name)
        {:error, error} -> {:error, error}
      end
    end

    # Look up the credential record (and its owning user) by credential_id.
    # Used during the sign-in ceremony so we can supply Wax with the cose_key
    # required to verify the assertion signature, and so we can issue a token
    # for the right user without needing the identity field to be supplied
    # (passwordless / discoverable flow).
    #
    # Uses `authorize?: false` (rather than relying on the
    # `AshAuthenticationInteraction` policy bypass) because the loaded `:user`
    # relationship triggers a separate `Ash.Query` for the user resource that
    # doesn't inherit our context, and the WebAuthn ceremony has already
    # established the caller's identity by virtue of the assertion signature.
    defp lookup_credential_and_user(strategy, raw_id, tenant) do
      ash_opts = lookup_ash_opts(strategy, tenant)

      strategy.credential_resource
      |> Query.new()
      |> Query.set_context(auth_context())
      |> Query.filter(^ref(strategy.credential_id_field) == ^raw_id)
      |> Query.load(strategy.user_relationship_name)
      |> Ash.read_one(ash_opts)
      |> case do
        {:ok, nil} ->
          {:error, auth_failed(strategy, :sign_in, "Unknown credential")}

        {:ok, credential} ->
          case Map.get(credential, strategy.user_relationship_name) do
            nil ->
              {:error, auth_failed(strategy, :sign_in, "Credential is not linked to a user")}

            user ->
              {:ok, credential, user}
          end

        {:error, error} ->
          {:error, auth_failed(strategy, :sign_in, inspect(error))}
      end
    end

    # 2FA verify lookup: requires the credential to belong to `actor`. Prevents
    # an attacker from presenting a different user's credential during the
    # second-factor step.
    defp lookup_credential_for_actor(strategy, raw_id, actor, tenant) do
      ash_opts = lookup_ash_opts(strategy, tenant)
      [primary_key] = Ash.Resource.Info.primary_key(strategy.resource)
      actor_id = Map.fetch!(actor, primary_key)

      relationship =
        Ash.Resource.Info.relationship(
          strategy.credential_resource,
          strategy.user_relationship_name
        )

      foreign_key = relationship.source_attribute

      strategy.credential_resource
      |> Query.new()
      |> Query.set_context(auth_context())
      |> Query.filter(^ref(strategy.credential_id_field) == ^raw_id)
      |> Query.filter(^ref(foreign_key) == ^actor_id)
      |> Ash.read_one(ash_opts)
      |> case do
        {:ok, nil} ->
          {:error, auth_failed(strategy, :verify, "Unknown credential for this user")}

        {:ok, credential} ->
          {:ok, credential, actor}

        {:error, error} ->
          {:error, auth_failed(strategy, :verify, inspect(error))}
      end
    end

    defp lookup_ash_opts(strategy, tenant) do
      [authorize?: false, domain: Info.domain!(strategy.resource)]
      |> then(fn opts -> if tenant, do: Keyword.put(opts, :tenant, tenant), else: opts end)
    end

    # If the caller supplied an identity value (i.e. the form's identity field
    # was filled in), make sure the credential we resolved actually belongs to
    # that user. For the fully-discoverable flow (no identity submitted) we
    # trust the credential's own ownership.
    defp verify_identity_matches(strategy, action_name, params, user) do
      identity_value = params[to_string(strategy.identity_field)]

      cond do
        is_nil(identity_value) or identity_value == "" ->
          :ok

        Map.get(user, strategy.identity_field) |> to_string() == to_string(identity_value) ->
          :ok

        true ->
          {:error, auth_failed(strategy, action_name, "Identity does not match credential owner")}
      end
    end

    @doc "List all credentials for a user."
    @spec list_credentials(WebAuthn.t(), Ash.Resource.Record.t(), keyword) ::
            {:ok, [Ash.Resource.Record.t()]} | {:error, any}
    def list_credentials(strategy, user, opts) do
      ash_opts = internal_ash_opts(Keyword.get(opts, :tenant))

      strategy.credential_resource
      |> Query.new()
      |> Query.set_context(auth_context())
      |> Query.for_read(:read, %{}, ash_opts)
      |> Query.filter(user_id == ^user.id)
      |> maybe_sort_by_inserted_at(strategy)
      |> Ash.read()
    end

    # Sort by `:inserted_at` when the credential resource has it (the default
    # for fresh installs). Older / hand-rolled credential resources without
    # timestamps fall back to whatever order the data layer produces.
    defp maybe_sort_by_inserted_at(query, strategy) do
      if Ash.Resource.Info.attribute(strategy.credential_resource, :inserted_at) do
        Query.sort(query, inserted_at: :asc)
      else
        query
      end
    end

    @doc "Delete a credential, refusing to delete the last one."
    @spec delete_credential(WebAuthn.t(), Ash.Resource.Record.t(), any, keyword) ::
            :ok | {:error, any}
    def delete_credential(strategy, user, credential_id, opts) do
      with {:ok, credentials} <- list_credentials(strategy, user, opts),
           :ok <- ensure_not_last_credential(strategy, credentials),
           {:ok, credential} <- find_credential(strategy, credentials, credential_id) do
        destroy_credential(credential, opts)
      end
    end

    @doc "Update the label of a credential."
    @spec update_credential_label(WebAuthn.t(), any, String.t(), keyword) ::
            {:ok, Ash.Resource.Record.t()} | {:error, any}
    def update_credential_label(strategy, credential_id, new_label, opts) do
      ash_opts = internal_ash_opts(Keyword.get(opts, :tenant))

      with {:ok, credential} <- Ash.get(strategy.credential_resource, credential_id, ash_opts) do
        credential
        |> Changeset.new()
        |> Changeset.set_context(auth_context())
        |> Changeset.for_update(:update, %{label: new_label}, ash_opts)
        |> Ash.update()
      end
    end

    @doc """
    Add a new WebAuthn credential to an existing user.

    This is used when a user wants to register an additional security key or passkey.
    Unlike `register/3`, this does NOT create a new user - it attaches a credential
    to an existing one.

    Params should include:
    - `"attestation_object"` - Base64url-encoded attestation object from the browser
    - `"client_data_json"` - Base64url-encoded client data JSON from the browser
    - `"label"` - Optional human-readable label for the credential

    Options must include:
    - `challenge:` - The Wax.Challenge used for this ceremony
    - `user:` - The existing user to attach the credential to
    """
    @spec add_credential(WebAuthn.t(), map, keyword) ::
            {:ok, Ash.Resource.Record.t()} | {:error, any}
    def add_credential(strategy, params, opts \\ []) do
      challenge = Keyword.fetch!(opts, :challenge)
      user = Keyword.fetch!(opts, :user)
      tenant = Keyword.get(opts, :tenant)

      with {:ok, attestation_object} <- safe_url_decode64(params["attestation_object"]),
           {:ok, client_data_json} <- safe_url_decode64(params["client_data_json"]),
           {:ok, {auth_data, _}} <-
             wax_register_credential(strategy, attestation_object, client_data_json, challenge) do
        store_credential(
          strategy,
          user,
          auth_data.attested_credential_data,
          auth_data.sign_count,
          params["label"],
          tenant
        )
      else
        :error -> base64_error(strategy, :add_credential)
        {:error, error} -> {:error, error}
      end
    end

    defp wax_register_credential(strategy, attestation_object, client_data_json, challenge) do
      case Wax.register(attestation_object, client_data_json, challenge) do
        {:ok, _} = success ->
          success

        {:error, error} ->
          {:error, auth_failed(strategy, :add_credential, inspect(error))}
      end
    end

    defp wax_register(strategy, attestation_object, client_data_json, challenge) do
      case Wax.register(attestation_object, client_data_json, challenge) do
        {:ok, _} = success ->
          success

        {:error, error} ->
          {:error, auth_failed(strategy, :register, inspect(error))}
      end
    end

    defp wax_authenticate(
           strategy,
           action_name,
           raw_id,
           authenticator_data,
           signature,
           client_data_json,
           challenge,
           credentials
         ) do
      case Wax.authenticate(
             raw_id,
             authenticator_data,
             signature,
             client_data_json,
             challenge,
             credentials
           ) do
        {:ok, _} = success ->
          success

        {:error, error} ->
          {:error, auth_failed(strategy, action_name, inspect(error))}
      end
    end

    defp create_user_from_registration(strategy, auth_data, params, opts) do
      tenant = Keyword.get(opts, :tenant)
      cred_data = auth_data.attested_credential_data
      identity_key = to_string(strategy.identity_field)

      action_params = %{
        identity_key => params[identity_key],
        "credential_id" => cred_data.credential_id,
        "public_key" => cred_data.credential_public_key,
        "sign_count" => auth_data.sign_count,
        "label" => params["label"] || "Security Key"
      }

      ash_opts = build_ash_opts(strategy, opts, tenant)

      strategy.resource
      |> Changeset.new()
      |> Changeset.set_context(Map.put(auth_context(), :token_type, :sign_in))
      |> Changeset.for_create(strategy.register_action_name, action_params, ash_opts)
      |> Ash.create()
    end

    defp store_credential_from_auth(strategy, user, auth_data, params, opts) do
      tenant = Keyword.get(opts, :tenant)
      cred_data = auth_data.attested_credential_data
      store_credential(strategy, user, cred_data, auth_data.sign_count, params["label"], tenant)
    end

    defp best_effort_update_sign_count(strategy, credential_id, new_count, tenant) do
      update_sign_count(strategy, credential_id, new_count, tenant)
      :ok
    end

    defp ensure_not_last_credential(strategy, credentials) do
      if length(credentials) <= 1 do
        {:error, auth_failed(strategy, :delete_credential, "Cannot delete the last credential")}
      else
        :ok
      end
    end

    defp find_credential(strategy, credentials, credential_id) do
      case Enum.find(credentials, &(&1.id == credential_id)) do
        nil -> {:error, auth_failed(strategy, :delete_credential, "Credential not found")}
        credential -> {:ok, credential}
      end
    end

    defp destroy_credential(credential, opts) do
      tenant = Keyword.get(opts, :tenant)
      ash_opts = [authorize?: false]
      ash_opts = if tenant, do: Keyword.put(ash_opts, :tenant, tenant), else: ash_opts

      credential
      |> Changeset.new()
      |> Changeset.set_context(auth_context())
      |> Ash.destroy(ash_opts)
    end

    defp build_ash_opts(strategy, opts, tenant) do
      ash_opts =
        opts
        |> Keyword.take([:actor])
        |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

      if tenant, do: Keyword.put(ash_opts, :tenant, tenant), else: ash_opts
    end

    defp auth_context, do: %{private: %{ash_authentication?: true}}

    defp auth_failed(strategy, action, message) do
      AuthenticationFailed.exception(
        strategy: strategy,
        caused_by: %{
          module: __MODULE__,
          strategy: strategy,
          action: action,
          message: message
        }
      )
    end

    defp base64_error(strategy, action) do
      {:error, auth_failed(strategy, action, "Invalid base64 encoding in request parameters")}
    end

    defp store_credential(strategy, user, cred_data, sign_count, label, tenant) do
      attrs = %{
        credential_id: cred_data.credential_id,
        public_key: cred_data.credential_public_key,
        sign_count: sign_count,
        label: label || "Security Key",
        user_id: user.id
      }

      ash_opts = internal_ash_opts(tenant)

      strategy.credential_resource
      |> Changeset.new()
      |> Changeset.set_context(auth_context())
      |> Changeset.for_create(:create, attrs, ash_opts)
      |> Ash.create()
    end

    defp update_sign_count(strategy, credential_id, new_count, tenant) do
      ash_opts = internal_ash_opts(tenant)

      strategy.credential_resource
      |> Query.new()
      |> Query.set_context(auth_context())
      |> Query.for_read(:read, %{}, ash_opts)
      |> Query.filter(credential_id == ^credential_id)
      |> Ash.read_one()
      |> case do
        {:ok, nil} ->
          :ok

        {:ok, credential} ->
          credential
          |> Changeset.new()
          |> Changeset.set_context(auth_context())
          |> Changeset.for_update(
            :update,
            %{sign_count: new_count, last_used_at: DateTime.utc_now()},
            ash_opts
          )
          |> Ash.update()
          |> case do
            {:ok, _} -> :ok
            {:error, error} -> log_sign_count_failure(error)
          end

        {:error, error} ->
          log_sign_count_failure(error)
      end
    end

    defp log_sign_count_failure(error) do
      Logger.warning("Failed to update WebAuthn sign count: #{inspect(error)}")
      :ok
    end

    defp internal_ash_opts(tenant) do
      ash_opts = [authorize?: false]
      if tenant, do: Keyword.put(ash_opts, :tenant, tenant), else: ash_opts
    end

    defp maybe_generate_token(user, strategy, opts) do
      if Info.authentication_tokens_enabled?(strategy.resource) do
        case Jwt.token_for_user(user, %{"purpose" => "sign_in"}, Keyword.take(opts, [:tenant])) do
          {:ok, token, _claims} ->
            {:ok, Ash.Resource.put_metadata(user, :token, token)}

          {:error, error} ->
            {:error, error}
        end
      else
        {:ok, user}
      end
    end

    # Like `maybe_generate_token/3`, but bakes the verification timestamp into
    # the token's claims so headless / API clients can prove second-factor
    # status without relying on session metadata.
    defp maybe_generate_verified_token(user, strategy, opts, verified_at) do
      if Info.authentication_tokens_enabled?(strategy.resource) do
        claims = %{
          "purpose" => "sign_in",
          "webauthn_verified_at" => DateTime.to_iso8601(verified_at)
        }

        case Jwt.token_for_user(user, claims, Keyword.take(opts, [:tenant])) do
          {:ok, token, _claims} ->
            {:ok, Ash.Resource.put_metadata(user, :token, token)}

          {:error, error} ->
            {:error, error}
        end
      else
        {:ok, user}
      end
    end

    defp safe_url_decode64(nil), do: :error

    defp safe_url_decode64(value) when is_binary(value),
      do: Base.url_decode64(value, padding: false)

    defp safe_url_decode64(_), do: :error
  else
    def registration_challenge(strategy, _tenant, _opts \\ []),
      do: missing_wax_dependency(strategy, :registration_challenge)

    def authentication_challenge(strategy, _allow_credentials, _tenant, _opts \\ []),
      do: missing_wax_dependency(strategy, :authentication_challenge)

    def register(strategy, _params, _opts \\ []),
      do: missing_wax_dependency(strategy, :register)

    def sign_in_with_token(strategy, _params, _opts \\ []),
      do: missing_wax_dependency(strategy, :sign_in_with_token)

    def sign_in(strategy, _params, _opts \\ []),
      do: missing_wax_dependency(strategy, :sign_in)

    def verify(strategy, _params, _opts \\ []),
      do: missing_wax_dependency(strategy, :verify)

    def list_credentials(strategy, _user, _opts),
      do: missing_wax_dependency(strategy, :list_credentials)

    def delete_credential(strategy, _user, _credential_id, _opts),
      do: missing_wax_dependency(strategy, :delete_credential)

    def update_credential_label(strategy, _credential_id, _new_label, _opts),
      do: missing_wax_dependency(strategy, :update_credential_label)

    def add_credential(strategy, _params, _opts \\ []),
      do: missing_wax_dependency(strategy, :add_credential)

    defp missing_wax_dependency(strategy, action) do
      {:error,
       AuthenticationFailed.exception(
         strategy: strategy,
         caused_by: %{
           module: __MODULE__,
           strategy: strategy,
           action: action,
           message: "The WebAuthn strategy requires the optional `:wax_` dependency"
         }
       )}
    end
  end
end
