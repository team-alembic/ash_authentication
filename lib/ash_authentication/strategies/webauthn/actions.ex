defmodule AshAuthentication.Strategy.WebAuthn.Actions do
  @moduledoc """
  Core action implementations for the WebAuthn strategy.

  Wraps the `wax_` library for FIDO2 ceremony handling and coordinates
  with Ash to persist users and credentials.
  """

  alias Ash.{Changeset, Query}
  alias AshAuthentication.{Errors.AuthenticationFailed, Info, Jwt, Strategy.WebAuthn}
  require Ash.Query
  require Logger

  @doc "Generate a registration challenge."
  @spec registration_challenge(WebAuthn.t(), any) :: {:ok, Wax.Challenge.t()}
  def registration_challenge(strategy, tenant) do
    opts = WebAuthn.Helpers.wax_opts(strategy, tenant)
    challenge = Wax.new_registration_challenge(opts)
    {:ok, challenge}
  end

  @doc "Generate an authentication challenge."
  @spec authentication_challenge(WebAuthn.t(), list, any) :: {:ok, Wax.Challenge.t()}
  def authentication_challenge(strategy, allow_credentials, tenant) do
    opts =
      strategy
      |> WebAuthn.Helpers.wax_opts(tenant)
      |> Keyword.put(:allow_credentials, allow_credentials)

    challenge = Wax.new_authentication_challenge(opts)
    {:ok, challenge}
  end

  @doc "Register a new user with a WebAuthn credential."
  @spec register(WebAuthn.t(), map, keyword) :: {:ok, Ash.Resource.record()} | {:error, any}
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

  @doc "Sign in a user with a WebAuthn credential."
  @spec sign_in(WebAuthn.t(), map, keyword) :: {:ok, Ash.Resource.record()} | {:error, any}
  def sign_in(strategy, params, opts \\ []) do
    challenge = Keyword.fetch!(opts, :challenge)
    tenant = Keyword.get(opts, :tenant)

    with {:ok, raw_id} <- safe_url_decode64(params["raw_id"]),
         {:ok, authenticator_data} <- safe_url_decode64(params["authenticator_data"]),
         {:ok, signature} <- safe_url_decode64(params["signature"]),
         {:ok, client_data_json} <- safe_url_decode64(params["client_data_json"]),
         {:ok, auth_data} <-
           wax_authenticate(
             strategy,
             raw_id,
             authenticator_data,
             signature,
             client_data_json,
             challenge
           ),
         {:ok, user} <- find_user_for_sign_in(strategy, params, opts),
         :ok <- best_effort_update_sign_count(strategy, raw_id, auth_data.sign_count, tenant) do
      maybe_generate_token(user, strategy, opts)
    else
      :error -> base64_error(strategy, :sign_in)
      {:error, error} -> {:error, error}
    end
  end

  @doc "List all credentials for a user."
  @spec list_credentials(WebAuthn.t(), Ash.Resource.record(), keyword) ::
          {:ok, [Ash.Resource.record()]} | {:error, any}
  def list_credentials(strategy, user, opts) do
    ash_opts = internal_ash_opts(Keyword.get(opts, :tenant))

    strategy.credential_resource
    |> Query.new()
    |> Query.set_context(auth_context())
    |> Query.for_read(:read, %{}, ash_opts)
    |> Query.filter(user_id == ^user.id)
    |> Query.sort(inserted_at: :asc)
    |> Ash.read()
  end

  @doc "Delete a credential, refusing to delete the last one."
  @spec delete_credential(WebAuthn.t(), Ash.Resource.record(), any, keyword) ::
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
          {:ok, Ash.Resource.record()} | {:error, any}
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
          {:ok, Ash.Resource.record()} | {:error, any}
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
         raw_id,
         authenticator_data,
         signature,
         client_data_json,
         challenge
       ) do
    case Wax.authenticate(raw_id, authenticator_data, signature, client_data_json, challenge) do
      {:ok, _} = success ->
        success

      {:error, error} ->
        {:error, auth_failed(strategy, :sign_in, inspect(error))}
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
    |> Changeset.set_context(auth_context())
    |> Changeset.for_create(strategy.register_action_name, action_params, ash_opts)
    |> Ash.create()
  end

  defp store_credential_from_auth(strategy, user, auth_data, params, opts) do
    tenant = Keyword.get(opts, :tenant)
    cred_data = auth_data.attested_credential_data
    store_credential(strategy, user, cred_data, auth_data.sign_count, params["label"], tenant)
  end

  defp find_user_for_sign_in(strategy, params, opts) do
    tenant = Keyword.get(opts, :tenant)
    identity_value = params[to_string(strategy.identity_field)]
    ash_opts = build_ash_opts(strategy, opts, tenant)

    strategy.resource
    |> Query.new()
    |> Query.set_context(auth_context())
    |> Query.for_read(
      strategy.sign_in_action_name,
      %{strategy.identity_field => identity_value},
      ash_opts
    )
    |> Ash.read()
    |> handle_user_query_result(strategy)
  end

  defp handle_user_query_result({:ok, [user]}, _strategy), do: {:ok, user}

  defp handle_user_query_result({:ok, []}, strategy),
    do: {:error, auth_failed(strategy, :sign_in, "Query returned no users")}

  defp handle_user_query_result({:ok, _}, strategy),
    do: {:error, auth_failed(strategy, :sign_in, "Query returned too many users")}

  defp handle_user_query_result({:error, %AuthenticationFailed{} = error}, _strategy),
    do: {:error, error}

  defp handle_user_query_result({:error, error}, strategy) when is_exception(error),
    do: {:error, AuthenticationFailed.exception(strategy: strategy, caused_by: error)}

  defp handle_user_query_result({:error, _}, strategy),
    do: {:error, auth_failed(strategy, :sign_in, "Authentication failed")}

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
      case Jwt.token_for_user(user, %{"purpose" => "user"}, Keyword.take(opts, [:tenant])) do
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
end
