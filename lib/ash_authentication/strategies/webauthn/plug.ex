# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Plug do
  @moduledoc """
  Plug handlers for the WebAuthn strategy.

  Handles registration challenges, registration, authentication challenges,
  and authentication via HTTP requests. Challenges are stored in the Plug
  session, each paired with a short-lived token that the ceremony consumes,
  so a challenge can only be answered once whatever the session store.

  Everything that depends on the ceremony backend — the challenge itself,
  the algorithms advertised to the browser, verification — goes through the
  strategy's adapter. Nothing is taken from the request's own scheme, host
  or port: the origin a ceremony is accepted from is the strategy's policy
  (see `AshAuthentication.Strategy.WebAuthn.Origin`), so the plugs behave
  the same behind a TLS-terminating proxy as without one.
  """

  alias AshAuthentication.{
    Errors.AuthenticationFailed,
    Info,
    Jwt,
    Strategy,
    Strategy.WebAuthn,
    TokenResource
  }

  alias Plug.Conn
  import Ash.PlugHelpers, only: [get_actor: 1, get_tenant: 1, get_context: 1]
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]
  require Logger

  # Challenges are stored per ceremony type and per strategy so concurrent
  # ceremonies — a registration in one tab and a sign-in in another, or two
  # differently-named strategies on the same resource — don't clobber each
  # other's session entry. Two concurrent ceremonies of the *same* type and
  # strategy still share a slot; the later challenge wins, which is the
  # correct freshness behavior for a retried ceremony.
  defp session_key(strategy, type), do: "webauthn_#{type}_challenge_#{strategy.name}"

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

    {:ok, challenge} = WebAuthn.Actions.registration_challenge(strategy, tenant)

    rp_id = WebAuthn.Helpers.resolve_rp_id(strategy, tenant)
    rp_name = WebAuthn.Helpers.resolve_rp_name(strategy, tenant)

    response =
      %{
        challenge: Base.url_encode64(strategy.adapter.challenge_bytes(challenge), padding: false),
        rp: %{id: rp_id, name: rp_name},
        user: user_descriptor,
        # The algorithms the adapter can verify: an authenticator only creates
        # a credential with one of these, so the list decides what the server
        # will later be able to check.
        pubKeyCredParams: strategy.adapter.pub_key_cred_params(),
        excludeCredentials:
          Enum.map(
            exclude_credential_ids,
            &%{id: Base.url_encode64(&1, padding: false), type: "public-key"}
          ),
        authenticatorSelection: authenticator_selection(strategy),
        extensions: %{credProps: true},
        attestation: strategy.attestation,
        timeout: strategy.timeout
      }
      |> put_hints(resolve_hints(conn, strategy))

    # The user handle rides along with the adapter's session-safe challenge
    # data so registration can persist it.
    challenge_data =
      challenge
      |> strategy.adapter.serialize_challenge()
      |> Map.put(:user_handle, user_descriptor.id)

    send_challenge(conn, strategy, :attestation, challenge_data, response)
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

  @doc """
  Generate and return an authentication challenge.

  The challenge never lists credentials (`allowCredentials` is empty), so
  sign-in always uses a discoverable credential and the user is resolved
  from the credential id the authenticator returns. Any identity in the
  request is ignored here; `sign_in/2` still checks a submitted identity
  against the credential's owner.
  """
  @spec authentication_challenge(Conn.t(), WebAuthn.t()) :: Conn.t()
  def authentication_challenge(conn, strategy) do
    tenant = get_tenant(conn)

    # `allowCredentials` is intentionally left empty, for the same reason as
    # `excludeCredentials` in `registration_challenge/2`: this endpoint is
    # public and unauthenticated, so filling it from a submitted identity
    # would hand that user's credential ids — and whether the account
    # exists — to anyone who knows or guesses the identity. The cost is that
    # only discoverable credentials can sign in; the verifier warns when
    # `resident_key` allows any other kind to be created.
    {:ok, challenge} = WebAuthn.Actions.authentication_challenge(strategy, [], tenant)

    response = assertion_options(conn, strategy, challenge, [], tenant)
    challenge_data = strategy.adapter.serialize_challenge(challenge)

    send_challenge(conn, strategy, :authentication, challenge_data, response)
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
          WebAuthn.Actions.authentication_challenge(strategy, allow_credentials, tenant)

        response = assertion_options(conn, strategy, challenge, credentials, tenant)
        challenge_data = strategy.adapter.serialize_challenge(challenge)

        send_challenge(conn, strategy, :authentication, challenge_data, response)
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
    with actor when not is_nil(actor) <- get_actor(conn),
         :ok <-
           WebAuthn.RecentAuthentication.check(
             strategy,
             actor,
             authentication_opts(conn, actor)
           ) do
      credentials = load_actor_credentials(strategy, actor, get_tenant(conn))
      user_descriptor = actor_user_descriptor(strategy, actor, credentials)

      exclude_ids =
        Enum.map(credentials, &Map.get(&1, WebAuthn.credential_id_field(strategy)))

      send_registration_challenge(conn, strategy, user_descriptor, exclude_ids)
    else
      nil -> store_authentication_result(conn, unauthenticated_error(strategy, :add_credential))
      {:error, error} -> store_authentication_result(conn, {:error, error})
    end
  end

  # A bearer-authenticated actor carries no session token in its metadata,
  # so hand `RecentAuthentication` the issue time of the bearer token the
  # request presented — provided it was issued to this actor.
  defp authentication_opts(conn, actor) do
    conn
    |> Conn.get_req_header("authorization")
    |> Enum.find_value(fn
      "Bearer " <> token -> WebAuthn.RecentAuthentication.token_issued_at(token, actor)
      _ -> nil
    end)
    |> case do
      nil -> []
      at -> [authenticated_at: at]
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

      opts =
        opts(conn) ++
          [challenge: challenge, user: actor, user_handle: user_handle] ++
          authentication_opts(conn, actor)

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

  # Deleting a challenge from the session only removes it from the *next*
  # cookie: with a cookie session store the client still holds the one it
  # was issued, challenge and all. So each challenge is paired with a token
  # that lives exactly as long as the ceremony may, and `reconstruct_challenge/3`
  # revokes it on first use — the token resource then refuses the challenge
  # in any cookie it arrives in.
  defp send_challenge(conn, strategy, type, challenge_data, response) do
    case challenge_token(conn, strategy) do
      {:ok, token} ->
        conn
        |> Conn.put_session(session_key(strategy, type), Map.put(challenge_data, :token, token))
        |> Conn.put_resp_content_type("application/json")
        |> Conn.send_resp(200, Jason.encode!(response))

      {:error, error} ->
        store_authentication_result(conn, {:error, error})
    end
  end

  defp challenge_token(conn, strategy) do
    opts =
      [
        purpose: :webauthn_challenge,
        token_lifetime: {WebAuthn.Helpers.challenge_timeout_seconds(strategy), :seconds}
      ] ++ Keyword.take(opts(conn), [:tenant])

    case Jwt.token_for_resource(strategy.resource, %{}, opts, get_context(conn) || %{}) do
      {:ok, token, _claims} -> {:ok, token}
      {:error, error} -> {:error, error}
    end
  end

  # Rebuild the ceremony challenge from the serialized session data via the
  # strategy's adapter (challenges are stored as plain maps because cookie
  # session stores cannot serialize arbitrary Elixir structs). Consumes the
  # challenge's token first, so a challenge that was already answered, or
  # whose token has expired, comes back as `nil`.
  defp reconstruct_challenge(conn, type, strategy) do
    with %{} = data <- Conn.get_session(conn, session_key(strategy, type)),
         :ok <- consume_challenge_token(conn, strategy, data) do
      strategy.adapter.deserialize_challenge(strategy, data, type)
    else
      _ -> nil
    end
  end

  # The revocation is the serialisation point: of any number of concurrent
  # uses, exactly one revokes the token.
  defp consume_challenge_token(conn, strategy, data) do
    opts = Keyword.take(opts(conn), [:tenant, :context])

    with token when is_binary(token) <- data[:token] || data["token"],
         {:ok, %{"purpose" => "webauthn_challenge"}, _resource} <-
           Jwt.verify(
             token,
             strategy.resource,
             Keyword.take(opts, [:tenant]),
             get_context(conn) || %{}
           ),
         {:ok, token_resource} when token_resource not in [nil, false] <-
           Info.authentication_tokens_token_resource(strategy.resource),
         :ok <-
           TokenResource.revoke(
             token_resource,
             token,
             Keyword.put(
               opts,
               :store_all_tokens?,
               Info.authentication_tokens_store_all_tokens?(strategy.resource)
             )
           ) do
      :ok
    else
      _ -> :error
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

  # The `PublicKeyCredentialRequestOptions` sent to the browser. Shared by
  # sign-in and second-factor verification, which differ only in how they
  # arrive at their candidate credentials.
  defp assertion_options(conn, strategy, challenge, credentials, tenant) do
    %{
      challenge: Base.url_encode64(strategy.adapter.challenge_bytes(challenge), padding: false),
      rpId: WebAuthn.Helpers.resolve_rp_id(strategy, tenant),
      userVerification: strategy.user_verification,
      timeout: strategy.timeout,
      allowCredentials: allow_credentials_entries(strategy, credentials)
    }
    |> put_hints(resolve_hints(conn, strategy))
  end

  # `authenticatorAttachment` is a three-valued enum with no member for "no
  # preference" — the absence of the key is how that is expressed, and
  # `null` is not a legal value. Sending it explicitly also competes with
  # `hints`, which supersedes it.
  defp authenticator_selection(strategy) do
    %{
      userVerification: strategy.user_verification,
      residentKey: strategy.resident_key,
      # The Level 1 spelling, for clients predating `residentKey`.
      requireResidentKey: strategy.resident_key == :required
    }
    |> maybe_put(:authenticatorAttachment, attachment(strategy.authenticator_attachment))
  end

  # The DSL spells this option in snake case; the enum member is hyphenated,
  # and a client which doesn't recognise the value ignores the whole member.
  defp attachment(:cross_platform), do: "cross-platform"
  defp attachment(:platform), do: "platform"
  defp attachment(nil), do: nil

  defp maybe_put(map, _key, nil), do: map
  defp maybe_put(map, key, value), do: Map.put(map, key, value)

  @hint_strings %{
    security_key: "security-key",
    client_device: "client-device",
    hybrid: "hybrid"
  }
  @valid_hints Map.values(@hint_strings)

  # An empty `hints` means "no preference", which is spelled by leaving the
  # member out — an empty sequence reads to some clients as "nothing is
  # acceptable".
  defp put_hints(response, []), do: response
  defp put_hints(response, hints), do: Map.put(response, :hints, hints)

  # `hints` only steers the dialog the requesting browser shows itself, so a
  # request-supplied value can be honoured without ceding anything: every
  # option that bears on verification is server-derived and re-applied from
  # the session-stored challenge. Unrecognised values are dropped rather than
  # rejected, since a client is free to send hints this version has never
  # heard of.
  defp resolve_hints(conn, strategy) do
    with true <- strategy.allow_hint_override?,
         [_ | _] = hints <- requested_hints(conn) do
      hints
    else
      _ -> Enum.map(strategy.hints, &Map.fetch!(@hint_strings, &1))
    end
  end

  defp requested_hints(conn) do
    conn.params
    |> Map.get("hints")
    |> List.wrap()
    |> Enum.flat_map(fn
      hint when is_binary(hint) -> String.split(hint, ",", trim: true)
      _ -> []
    end)
    |> Enum.map(&(&1 |> String.trim() |> String.downcase()))
    |> Enum.filter(&(&1 in @valid_hints))
    |> Enum.uniq()
    |> Enum.take(length(@valid_hints))
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
end
