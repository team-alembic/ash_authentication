# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Wax.Challenge) do
  defmodule AshAuthentication.Strategy.WebAuthn.Plug do
    @moduledoc """
    Plug handlers for the WebAuthn strategy.

    Handles registration challenges, registration, authentication challenges,
    and authentication via HTTP requests. Challenges are stored in the Plug session.
    """

    alias AshAuthentication.{Errors.AuthenticationFailed, Info, Strategy, Strategy.WebAuthn}
    alias Plug.Conn
    import Ash.PlugHelpers, only: [get_actor: 1, get_tenant: 1, get_context: 1]
    import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]
    import Ash.Expr, only: [ref: 1]
    require Ash.Query
    require Logger

    # Challenges are stored per ceremony type and per strategy so concurrent
    # ceremonies — a registration in one tab and a sign-in in another, or two
    # differently-named strategies on the same resource — don't clobber each
    # other's session entry. Two concurrent ceremonies of the *same* type and
    # strategy still share a slot; the later challenge wins, which is the
    # correct freshness behavior for a retried ceremony.
    defp session_key(strategy, type), do: "webauthn_#{type}_challenge_#{strategy.name}"

    # COSE algorithms Wax can verify, in preference order. Deliberately
    # excludes RSASSA-PKCS1-v1_5 w/ SHA-1 (-65535) and ES256K (-47).
    @pub_key_cred_params Enum.map(
                           [-7, -8, -35, -36, -37, -38, -39, -257, -258, -259],
                           &%{type: "public-key", alg: &1}
                         )

    @doc "Generate and return a registration challenge."
    @spec registration_challenge(Conn.t(), WebAuthn.t()) :: Conn.t()
    def registration_challenge(conn, strategy) do
      # `excludeCredentials` is intentionally left empty. Populating it from the
      # submitted identity would turn this public, unauthenticated endpoint into
      # an oracle: it would return a user's real credential ids to anyone who
      # guesses their identity. The cost is that an authenticator won't refuse a
      # duplicate enrolment up front; the register action still rejects it via
      # its unique-credential-id constraint.
      send_registration_challenge(
        conn,
        strategy,
        new_user_descriptor(conn, strategy),
        []
      )
    end

    defp send_registration_challenge(conn, strategy, user_descriptor, exclude_credential_ids) do
      tenant = get_tenant(conn)

      {:ok, challenge} =
        WebAuthn.Actions.registration_challenge(strategy, tenant, origin: origin_from_conn(conn))

      rp_id = WebAuthn.Helpers.resolve_rp_id(strategy, tenant)
      rp_name = WebAuthn.Helpers.resolve_rp_name(strategy, tenant)

      response = %{
        challenge: Base.url_encode64(strategy.adapter.challenge_bytes(challenge), padding: false),
        rp: %{id: rp_id, name: rp_name},
        user: user_descriptor,
        pubKeyCredParams: @pub_key_cred_params,
        excludeCredentials:
          Enum.map(
            exclude_credential_ids,
            &%{id: Base.url_encode64(&1, padding: false), type: "public-key"}
          ),
        authenticatorSelection: %{
          authenticatorAttachment: strategy.authenticator_attachment,
          userVerification: strategy.user_verification,
          residentKey: strategy.resident_key
        },
        extensions: %{credProps: true},
        attestation: strategy.attestation,
        timeout: strategy.timeout
      }

      # The user handle rides along with the adapter's session-safe challenge
      # data so registration can persist it.
      challenge_data =
        challenge
        |> strategy.adapter.serialize_challenge()
        |> Map.put(:user_handle, user_descriptor.id)

      conn
      |> Conn.put_session(session_key(strategy, :attestation), challenge_data)
      |> Conn.put_resp_content_type("application/json")
      |> Conn.send_resp(200, Jason.encode!(response))
    end

    # The user handle (`user.id`) must be an opaque byte sequence of at most
    # 64 bytes without PII, so a fresh registration gets random bytes rather
    # than anything derived from the identity value. It is kept in the session
    # challenge data so the verifying side can associate it with the stored
    # credential.
    # `name` is the account identifier shown in the passkey picker (the
    # identity value when the flow has one); `displayName` is the friendly
    # name. Both are display-only and may be supplied as request params —
    # in passkey-first mode (no identity field) `display_name`/`name` params
    # are the only way to label the account inside the passkey.
    defp new_user_descriptor(conn, strategy) do
      identity = presence(conn.params[to_string(strategy.identity_field)])
      display_name = presence(conn.params["display_name"]) || presence(conn.params["name"])
      name = identity || display_name || "user"

      %{
        id: Base.url_encode64(:crypto.strong_rand_bytes(32), padding: false),
        name: name,
        displayName: display_name || name
      }
    end

    defp presence(value) when is_binary(value) and value != "", do: value
    defp presence(_), do: nil

    # For an existing user (add_credential flow) the handle must be stable so
    # all of the user's passkeys share it: reuse the handle stored with an
    # existing credential when there is one, otherwise fall back to the
    # primary key (stable, and what our discoverable-credential lookup
    # resolves anyway).
    defp actor_user_descriptor(strategy, actor, credentials) do
      [primary_key] = Ash.Resource.Info.primary_key(strategy.resource)

      handle =
        Enum.find_value(credentials, &Map.get(&1, WebAuthn.user_handle_field(strategy))) ||
          pk_handle(actor, primary_key)

      name =
        case Map.get(actor, strategy.identity_field) do
          nil -> pk_handle(actor, primary_key)
          value -> to_string(value)
        end

      %{
        id: Base.url_encode64(handle, padding: false),
        name: name,
        displayName: name
      }
    end

    defp pk_handle(actor, primary_key), do: actor |> Map.fetch!(primary_key) |> to_string()

    # Recover the user handle minted at challenge time so it can be stored
    # alongside the credential. Read before the session challenge is deleted.
    defp session_user_handle(conn, strategy) do
      with %{} = data <- Conn.get_session(conn, session_key(strategy, :attestation)),
           handle when is_binary(handle) <- data["user_handle"] || data[:user_handle],
           {:ok, bytes} <- Base.url_decode64(handle, padding: false) do
        bytes
      else
        _ -> nil
      end
    end

    @doc "Handle a registration request."
    @spec register(Conn.t(), WebAuthn.t()) :: Conn.t()
    def register(conn, strategy) do
      case reconstruct_challenge(conn, :attestation, strategy) do
        nil ->
          conn
          |> Conn.delete_session(session_key(strategy, :attestation))
          |> store_authentication_result(missing_challenge_error(strategy, :register))

        challenge ->
          user_handle = session_user_handle(conn, strategy)
          conn = Conn.delete_session(conn, session_key(strategy, :attestation))
          params = subject_params(conn, strategy)
          opts = opts(conn) ++ [challenge: challenge, user_handle: user_handle]
          result = Strategy.action(strategy, :register, params, opts)
          store_authentication_result(conn, result)
      end
    end

    @doc "Generate and return an authentication challenge."
    @spec authentication_challenge(Conn.t(), WebAuthn.t()) :: Conn.t()
    def authentication_challenge(conn, strategy) do
      tenant = get_tenant(conn)
      params = conn.params
      identity_value = params[to_string(strategy.identity_field)]

      # FIXED: Look up credentials for a SPECIFIC user, not all credentials
      credentials =
        if identity_value do
          lookup_user_credentials(strategy, identity_value, tenant)
        else
          # Discoverable credential flow (passkeys) - no allow_credentials needed
          []
        end

      allow_credentials = assertion_allow_credentials(strategy, credentials)

      {:ok, challenge} =
        WebAuthn.Actions.authentication_challenge(strategy, allow_credentials, tenant,
          origin: origin_from_conn(conn)
        )

      response = %{
        challenge: Base.url_encode64(strategy.adapter.challenge_bytes(challenge), padding: false),
        rpId: WebAuthn.Helpers.resolve_rp_id(strategy, tenant),
        userVerification: strategy.user_verification,
        timeout: strategy.timeout,
        allowCredentials: allow_credentials_entries(strategy, credentials)
      }

      challenge_data = strategy.adapter.serialize_challenge(challenge)

      conn
      |> Conn.put_session(session_key(strategy, :authentication), challenge_data)
      |> Conn.put_resp_content_type("application/json")
      |> Conn.send_resp(200, Jason.encode!(response))
    end

    @doc "Exchange a short-lived sign-in token for an authenticated session."
    @spec sign_in_with_token(Conn.t(), WebAuthn.t()) :: Conn.t()
    def sign_in_with_token(conn, strategy) do
      params = conn.params
      opts = opts(conn)
      result = Strategy.action(strategy, :sign_in_with_token, params, opts)
      store_authentication_result(conn, result)
    end

    @doc "Handle an authentication request."
    @spec sign_in(Conn.t(), WebAuthn.t()) :: Conn.t()
    def sign_in(conn, strategy) do
      case reconstruct_challenge(conn, :authentication, strategy) do
        nil ->
          conn
          |> Conn.delete_session(session_key(strategy, :authentication))
          |> store_authentication_result(missing_challenge_error(strategy, :sign_in))

        challenge ->
          conn = Conn.delete_session(conn, session_key(strategy, :authentication))
          params = subject_params(conn, strategy)
          opts = opts(conn) ++ [challenge: challenge]
          result = Strategy.action(strategy, :sign_in, params, opts)
          store_authentication_result(conn, result)
      end
    end

    @doc """
    Generate and return a verification (second-factor) challenge.

    Requires an authenticated actor on the connection. The actor's existing
    credentials are listed as `allow_credentials` so the browser only offers
    those.
    """
    @spec verify_challenge(Conn.t(), WebAuthn.t()) :: Conn.t()
    def verify_challenge(conn, strategy) do
      case get_actor(conn) do
        nil ->
          store_authentication_result(conn, unauthenticated_error(strategy, :verify_challenge))

        actor ->
          tenant = get_tenant(conn)
          credentials = load_actor_credentials(strategy, actor, tenant)
          allow_credentials = assertion_allow_credentials(strategy, credentials)

          {:ok, challenge} =
            WebAuthn.Actions.authentication_challenge(strategy, allow_credentials, tenant,
              origin: origin_from_conn(conn)
            )

          response = %{
            challenge:
              Base.url_encode64(strategy.adapter.challenge_bytes(challenge), padding: false),
            rpId: WebAuthn.Helpers.resolve_rp_id(strategy, tenant),
            userVerification: strategy.user_verification,
            timeout: strategy.timeout,
            allowCredentials: allow_credentials_entries(strategy, credentials)
          }

          challenge_data = strategy.adapter.serialize_challenge(challenge)

          conn
          |> Conn.put_session(session_key(strategy, :authentication), challenge_data)
          |> Conn.put_resp_content_type("application/json")
          |> Conn.send_resp(200, Jason.encode!(response))
      end
    end

    @doc """
    Handle a second-factor verify request — confirm that the assertion was
    signed by one of the authenticated actor's credentials. On success the
    actor's `:webauthn_verified_at` metadata is stamped and a fresh token
    carrying the same value as a JWT claim is issued.
    """
    @spec verify(Conn.t(), WebAuthn.t()) :: Conn.t()
    def verify(conn, strategy) do
      with actor when not is_nil(actor) <- get_actor(conn),
           challenge when not is_nil(challenge) <-
             reconstruct_challenge(conn, :authentication, strategy) do
        conn = Conn.delete_session(conn, session_key(strategy, :authentication))
        params = subject_params(conn, strategy)
        opts = opts(conn) ++ [challenge: challenge, actor: actor]
        result = Strategy.action(strategy, :verify, params, opts)
        store_authentication_result(conn, result)
      else
        nil ->
          store_authentication_result(conn, unauthenticated_error(strategy, :verify))
      end
    end

    @doc """
    Generate and return a registration challenge for adding a credential to the
    current user.

    Requires an authenticated actor on the connection.
    """
    @spec add_credential_challenge(Conn.t(), WebAuthn.t()) :: Conn.t()
    def add_credential_challenge(conn, strategy) do
      case get_actor(conn) do
        nil ->
          store_authentication_result(conn, unauthenticated_error(strategy, :add_credential))

        actor ->
          credentials = load_actor_credentials(strategy, actor, get_tenant(conn))
          user_descriptor = actor_user_descriptor(strategy, actor, credentials)

          exclude_ids =
            Enum.map(credentials, &Map.get(&1, WebAuthn.credential_id_field(strategy)))

          send_registration_challenge(conn, strategy, user_descriptor, exclude_ids)
      end
    end

    @doc """
    Handle an `add_credential` request — attach a new credential to the
    authenticated user.

    Requires an authenticated actor on the connection.
    """
    @spec add_credential(Conn.t(), WebAuthn.t()) :: Conn.t()
    def add_credential(conn, strategy) do
      with actor when not is_nil(actor) <- get_actor(conn),
           challenge when not is_nil(challenge) <-
             reconstruct_challenge(conn, :attestation, strategy) do
        user_handle = session_user_handle(conn, strategy)
        conn = Conn.delete_session(conn, session_key(strategy, :attestation))
        params = subject_params(conn, strategy)
        opts = opts(conn) ++ [challenge: challenge, user: actor, user_handle: user_handle]
        result = WebAuthn.Actions.add_credential(strategy, params, opts)
        store_authentication_result(conn, result)
      else
        nil ->
          store_authentication_result(conn, unauthenticated_error(strategy, :add_credential))
      end
    end

    defp unauthenticated_error(strategy, action) do
      {:error,
       AuthenticationFailed.exception(
         strategy: strategy,
         caused_by: %{
           module: __MODULE__,
           strategy: strategy,
           action: action,
           message: "An authenticated user is required to add a credential"
         }
       )}
    end

    defp missing_challenge_error(strategy, action) do
      {:error,
       AuthenticationFailed.exception(
         strategy: strategy,
         caused_by: %{
           module: __MODULE__,
           strategy: strategy,
           action: action,
           message: "Missing or invalid WebAuthn challenge in session"
         }
       )}
    end

    # Rebuild the ceremony challenge from the serialized session data via the
    # strategy's adapter (challenges are stored as plain maps because cookie
    # session stores cannot serialize arbitrary Elixir structs).
    defp reconstruct_challenge(conn, type, strategy) do
      case Conn.get_session(conn, session_key(strategy, type)) do
        %{} = data -> strategy.adapter.deserialize_challenge(strategy, data, type)
        _ -> nil
      end
    end

    defp subject_params(conn, strategy) do
      subject_name =
        strategy.resource
        |> Info.authentication_subject_name!()
        |> to_string()

      Map.get(conn.params, subject_name, %{})
    end

    defp opts(conn) do
      [actor: get_actor(conn), tenant: get_tenant(conn), context: get_context(conn)]
      |> Enum.reject(&is_nil(elem(&1, 1)))
    end

    defp origin_from_conn(%Conn{scheme: scheme, host: host, port: port}) do
      port_segment =
        cond do
          scheme == :http and port == 80 -> ""
          scheme == :https and port == 443 -> ""
          true -> ":#{port}"
        end

      "#{scheme}://#{host}#{port_segment}"
    end

    # The {credential_id, cose_key} pairs the adapter needs to verify an
    # assertion against the challenge.
    defp assertion_allow_credentials(strategy, credentials) do
      Enum.map(credentials, fn cred ->
        {Map.get(cred, WebAuthn.credential_id_field(strategy)),
         Map.get(cred, WebAuthn.public_key_field(strategy))}
      end)
    end

    # The allowCredentials entries sent to the browser. Transports hints (when
    # captured at registration) let the client route straight to the right
    # authenticator instead of prompting for every kind it supports.
    defp allow_credentials_entries(strategy, credentials) do
      Enum.map(credentials, fn cred ->
        entry = %{
          id:
            Base.url_encode64(Map.get(cred, WebAuthn.credential_id_field(strategy)),
              padding: false
            ),
          type: "public-key"
        }

        case Map.get(cred, WebAuthn.transports_field(strategy)) do
          [_ | _] = transports -> Map.put(entry, :transports, transports)
          _ -> entry
        end
      end)
    end

    defp load_actor_credentials(strategy, actor, tenant) do
      ash_opts = [authorize?: false]
      ash_opts = if tenant, do: Keyword.put(ash_opts, :tenant, tenant), else: ash_opts

      case Ash.load(actor, [strategy.credentials_relationship_name], ash_opts) do
        {:ok, loaded} ->
          Map.get(loaded, strategy.credentials_relationship_name, [])

        _ ->
          []
      end
    rescue
      error in [
        Ash.Error.Invalid,
        Ash.Error.Forbidden,
        Ash.Error.Framework,
        Ash.Error.Unknown
      ] ->
        Logger.warning("WebAuthn actor-credential lookup failed: #{Exception.message(error)}")

        []
    end

    # FIXED: Look up credentials for a SPECIFIC user by identity field.
    # The original version read ALL credentials for ALL users.
    defp lookup_user_credentials(strategy, identity_value, tenant) do
      context = %{private: %{ash_authentication?: true}}
      ash_opts = [authorize?: false]
      ash_opts = if tenant, do: Keyword.put(ash_opts, :tenant, tenant), else: ash_opts

      identity_field = strategy.identity_field

      # First find the user by identity
      with {:ok, user} when not is_nil(user) <-
             strategy.resource
             |> Ash.Query.new()
             |> Ash.Query.set_context(context)
             |> Ash.Query.filter(^ref(identity_field) == ^identity_value)
             |> Ash.Query.for_read(:read, %{}, ash_opts)
             |> Ash.read_one(),
           # Then load their credentials via the relationship
           {:ok, user} <-
             Ash.load(user, [strategy.credentials_relationship_name], ash_opts) do
        Map.get(user, strategy.credentials_relationship_name, [])
      else
        _ -> []
      end
    rescue
      error in [
        Ash.Error.Invalid,
        Ash.Error.Forbidden,
        Ash.Error.Framework,
        Ash.Error.Unknown
      ] ->
        Logger.warning("WebAuthn credential lookup failed: #{Exception.message(error)}")
        []
    end
  end
else
  defmodule AshAuthentication.Strategy.WebAuthn.Plug do
    @moduledoc """
    Plug handlers for the WebAuthn strategy.

    The WebAuthn plug requires the optional `:wax_` dependency.
    """

    alias AshAuthentication.Errors.AuthenticationFailed
    import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

    def registration_challenge(conn, strategy),
      do: missing_wax_dependency(conn, strategy, :registration_challenge)

    def register(conn, strategy),
      do: missing_wax_dependency(conn, strategy, :register)

    def authentication_challenge(conn, strategy),
      do: missing_wax_dependency(conn, strategy, :authentication_challenge)

    def sign_in(conn, strategy),
      do: missing_wax_dependency(conn, strategy, :sign_in)

    def sign_in_with_token(conn, strategy),
      do: missing_wax_dependency(conn, strategy, :sign_in_with_token)

    def verify_challenge(conn, strategy),
      do: missing_wax_dependency(conn, strategy, :verify_challenge)

    def verify(conn, strategy),
      do: missing_wax_dependency(conn, strategy, :verify)

    def add_credential_challenge(conn, strategy),
      do: missing_wax_dependency(conn, strategy, :add_credential_challenge)

    def add_credential(conn, strategy),
      do: missing_wax_dependency(conn, strategy, :add_credential)

    defp missing_wax_dependency(conn, strategy, action) do
      store_authentication_result(
        conn,
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
      )
    end
  end
end
