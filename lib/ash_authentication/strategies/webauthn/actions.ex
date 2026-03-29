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
    tenant = Keyword.get(opts, :tenant)

    with {:ok, attestation_object} <- safe_url_decode64(params["attestation_object"]),
         {:ok, client_data_json} <- safe_url_decode64(params["client_data_json"]) do
      case Wax.register(attestation_object, client_data_json, challenge) do
        {:ok, {auth_data, _attestation_result}} ->
          cred_data = auth_data.attested_credential_data

          # Only pass known action arguments - filter out raw WebAuthn ceremony data
          # (attestation_object, client_data_json, raw_id) that Ash doesn't accept
          identity_key = to_string(strategy.identity_field)

          action_params = %{
            identity_key => params[identity_key],
            "credential_id" => cred_data.credential_id,
            "public_key" => cred_data.credential_public_key,
            "sign_count" => auth_data.sign_count,
            "label" => params["label"] || "Security Key"
          }

          # CRITICAL: Set ash_authentication? context for policy bypass
          context = %{private: %{ash_authentication?: true}}

          ash_opts =
            opts
            |> Keyword.take([:actor])
            |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

          ash_opts = if tenant, do: Keyword.put(ash_opts, :tenant, tenant), else: ash_opts

          strategy.resource
          |> Changeset.new()
          |> Changeset.set_context(context)
          |> Changeset.for_create(strategy.register_action_name, action_params, ash_opts)
          |> Ash.create()
          |> case do
            {:ok, user} ->
              # Store the credential - errors here should propagate
              case store_credential(
                     strategy,
                     user,
                     cred_data,
                     auth_data.sign_count,
                     params["label"],
                     tenant
                   ) do
                {:ok, _credential} -> {:ok, user}
                {:error, error} -> {:error, error}
              end

            {:error, error} ->
              {:error, error}
          end

        {:error, error} ->
          {:error,
           AuthenticationFailed.exception(
             strategy: strategy,
             caused_by: %{
               module: __MODULE__,
               strategy: strategy,
               action: :register,
               message: inspect(error)
             }
           )}
      end
    else
      :error ->
        {:error,
         AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :register,
             message: "Invalid base64 encoding in request parameters"
           }
         )}
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
         {:ok, client_data_json} <- safe_url_decode64(params["client_data_json"]) do
      case Wax.authenticate(raw_id, authenticator_data, signature, client_data_json, challenge) do
        {:ok, auth_data} ->
          # Look up user via the sign_in action (SignInPreparation filters by identity)
          identity_value = params[to_string(strategy.identity_field)]

          # CRITICAL: Set ash_authentication? context (matches Password pattern)
          context = %{private: %{ash_authentication?: true}}

          ash_opts =
            opts
            |> Keyword.take([:actor])
            |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

          ash_opts = if tenant, do: Keyword.put(ash_opts, :tenant, tenant), else: ash_opts

          # Follow Password.Actions.sign_in pattern exactly:
          # Query.new -> set_context -> for_read -> Ash.read
          query =
            strategy.resource
            |> Query.new()
            |> Query.set_context(context)
            |> Query.for_read(
              strategy.sign_in_action_name,
              %{
                strategy.identity_field => identity_value
              },
              ash_opts
            )

          query
          |> Ash.read()
          |> case do
            {:ok, [user]} ->
              # Update sign count asynchronously (best-effort)
              update_sign_count(strategy, raw_id, auth_data.sign_count, tenant)

              # Generate token (WebAuthn does this here, not in preparation,
              # because Wax verification happens outside the Ash pipeline)
              case maybe_generate_token(user, strategy, opts) do
                {:ok, user} -> {:ok, user}
                {:error, error} -> {:error, error}
              end

            {:ok, []} ->
              {:error,
               AuthenticationFailed.exception(
                 strategy: strategy,
                 caused_by: %{
                   module: __MODULE__,
                   strategy: strategy,
                   action: :sign_in,
                   message: "Query returned no users"
                 }
               )}

            {:ok, _users} ->
              {:error,
               AuthenticationFailed.exception(
                 strategy: strategy,
                 caused_by: %{
                   module: __MODULE__,
                   strategy: strategy,
                   action: :sign_in,
                   message: "Query returned too many users"
                 }
               )}

            {:error, error} when is_struct(error, AuthenticationFailed) ->
              {:error, error}

            {:error, error} when is_exception(error) ->
              {:error,
               AuthenticationFailed.exception(
                 strategy: strategy,
                 caused_by: error
               )}

            {:error, _error} ->
              {:error,
               AuthenticationFailed.exception(
                 strategy: strategy,
                 caused_by: %{
                   module: __MODULE__,
                   strategy: strategy,
                   action: :sign_in,
                   message: "Authentication failed"
                 }
               )}
          end

        {:error, error} ->
          {:error,
           AuthenticationFailed.exception(
             strategy: strategy,
             caused_by: %{
               module: __MODULE__,
               strategy: strategy,
               action: :sign_in,
               message: inspect(error)
             }
           )}
      end
    else
      :error ->
        {:error,
         AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :sign_in,
             message: "Invalid base64 encoding in request parameters"
           }
         )}
    end
  end

  @doc "List all credentials for a user."
  @spec list_credentials(WebAuthn.t(), Ash.Resource.record(), keyword) ::
          {:ok, [Ash.Resource.record()]} | {:error, any}
  def list_credentials(strategy, user, opts) do
    tenant = Keyword.get(opts, :tenant)
    context = %{private: %{ash_authentication?: true}}
    ash_opts = [authorize?: false]
    ash_opts = if tenant, do: Keyword.put(ash_opts, :tenant, tenant), else: ash_opts

    strategy.credential_resource
    |> Query.new()
    |> Query.set_context(context)
    |> Query.for_read(:read, %{}, ash_opts)
    |> Query.filter(user_id == ^user.id)
    |> Query.sort(inserted_at: :asc)
    |> Ash.read()
  end

  @doc "Delete a credential, refusing to delete the last one."
  @spec delete_credential(WebAuthn.t(), Ash.Resource.record(), any, keyword) ::
          :ok | {:error, any}
  def delete_credential(strategy, user, credential_id, opts) do
    tenant = Keyword.get(opts, :tenant)
    context = %{private: %{ash_authentication?: true}}
    ash_opts = [authorize?: false]
    ash_opts = if tenant, do: Keyword.put(ash_opts, :tenant, tenant), else: ash_opts

    with {:ok, credentials} <- list_credentials(strategy, user, opts) do
      if length(credentials) <= 1 do
        {:error,
         AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :delete_credential,
             message: "Cannot delete the last credential"
           }
         )}
      else
        credential = Enum.find(credentials, &(&1.id == credential_id))

        if credential do
          credential
          |> Changeset.new()
          |> Changeset.set_context(context)
          |> Ash.destroy(ash_opts)
          |> case do
            :ok -> :ok
            {:error, error} -> {:error, error}
          end
        else
          {:error,
           AuthenticationFailed.exception(
             strategy: strategy,
             caused_by: %{
               module: __MODULE__,
               strategy: strategy,
               action: :delete_credential,
               message: "Credential not found"
             }
           )}
        end
      end
    end
  end

  @doc "Update the label of a credential."
  @spec update_credential_label(WebAuthn.t(), any, String.t(), keyword) ::
          {:ok, Ash.Resource.record()} | {:error, any}
  def update_credential_label(strategy, credential_id, new_label, opts) do
    tenant = Keyword.get(opts, :tenant)
    context = %{private: %{ash_authentication?: true}}
    ash_opts = [authorize?: false]
    ash_opts = if tenant, do: Keyword.put(ash_opts, :tenant, tenant), else: ash_opts

    with {:ok, credential} <-
           strategy.credential_resource
           |> Ash.get(credential_id, ash_opts) do
      credential
      |> Changeset.new()
      |> Changeset.set_context(context)
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
         {:ok, client_data_json} <- safe_url_decode64(params["client_data_json"]) do
      case Wax.register(attestation_object, client_data_json, challenge) do
        {:ok, {auth_data, _result}} ->
          cred_data = auth_data.attested_credential_data

          store_credential(
            strategy,
            user,
            cred_data,
            auth_data.sign_count,
            params["label"],
            tenant
          )

        {:error, error} ->
          {:error,
           AuthenticationFailed.exception(
             strategy: strategy,
             caused_by: %{
               module: __MODULE__,
               strategy: strategy,
               action: :add_credential,
               message: inspect(error)
             }
           )}
      end
    else
      :error ->
        {:error,
         AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :add_credential,
             message: "Invalid base64 encoding in request parameters"
           }
         )}
    end
  end

  defp store_credential(strategy, user, cred_data, sign_count, label, tenant) do
    attrs = %{
      credential_id: cred_data.credential_id,
      public_key: cred_data.credential_public_key,
      sign_count: sign_count,
      label: label || "Security Key",
      user_id: user.id
    }

    # CRITICAL: authorize?: false + ash_authentication? context for internal operations
    context = %{private: %{ash_authentication?: true}}
    ash_opts = [authorize?: false]
    ash_opts = if tenant, do: Keyword.put(ash_opts, :tenant, tenant), else: ash_opts

    strategy.credential_resource
    |> Changeset.new()
    |> Changeset.set_context(context)
    |> Changeset.for_create(:create, attrs, ash_opts)
    |> Ash.create()
  end

  defp update_sign_count(strategy, credential_id, new_count, tenant) do
    context = %{private: %{ash_authentication?: true}}
    ash_opts = [authorize?: false]
    ash_opts = if tenant, do: Keyword.put(ash_opts, :tenant, tenant), else: ash_opts

    strategy.credential_resource
    |> Query.new()
    |> Query.set_context(context)
    |> Query.for_read(:read, %{}, ash_opts)
    |> Query.filter(credential_id == ^credential_id)
    |> Ash.read_one()
    |> case do
      {:ok, nil} ->
        :ok

      {:ok, credential} ->
        credential
        |> Changeset.new()
        |> Changeset.set_context(context)
        |> Changeset.for_update(
          :update,
          %{
            sign_count: new_count,
            last_used_at: DateTime.utc_now()
          },
          ash_opts
        )
        |> Ash.update!()

      {:error, error} ->
        Logger.warning("Failed to update WebAuthn sign count: #{inspect(error)}")
        :ok
    end
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
