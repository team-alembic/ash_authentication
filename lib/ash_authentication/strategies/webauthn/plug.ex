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

  @session_key "webauthn_challenge"

  @doc "Generate and return a registration challenge."
  @spec registration_challenge(Conn.t(), WebAuthn.t()) :: Conn.t()
  def registration_challenge(conn, strategy) do
    tenant = get_tenant(conn)
    {:ok, challenge} = WebAuthn.Actions.registration_challenge(strategy, tenant)

    rp_id = WebAuthn.Helpers.resolve_rp_id(strategy, tenant)
    rp_name = WebAuthn.Helpers.resolve_rp_name(strategy, tenant)

    response = %{
      challenge: Base.url_encode64(challenge.bytes, padding: false),
      rp: %{id: rp_id, name: rp_name},
      authenticatorSelection: %{
        authenticatorAttachment: strategy.authenticator_attachment,
        userVerification: strategy.user_verification,
        residentKey: strategy.resident_key
      },
      attestation: strategy.attestation,
      timeout: strategy.timeout
    }

    # Store challenge as serializable map (not struct) for cookie session stores
    challenge_data = %{
      bytes: Base.encode64(challenge.bytes),
      type: challenge.type,
      origin: challenge.origin,
      rp_id: challenge.rp_id,
      issued_at: challenge.issued_at
    }

    conn
    |> Conn.put_session(@session_key, challenge_data)
    |> Conn.put_resp_content_type("application/json")
    |> Conn.send_resp(200, Jason.encode!(response))
  end

  @doc "Handle a registration request."
  @spec register(Conn.t(), WebAuthn.t()) :: Conn.t()
  def register(conn, strategy) do
    case reconstruct_challenge(conn, :attestation, strategy) do
      nil ->
        conn
        |> Conn.delete_session(@session_key)
        |> store_authentication_result(missing_challenge_error(strategy, :register))

      challenge ->
        conn = Conn.delete_session(conn, @session_key)
        params = subject_params(conn, strategy)
        opts = opts(conn) ++ [challenge: challenge]
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
    allow_credentials =
      if identity_value do
        lookup_user_credentials(strategy, identity_value, tenant)
      else
        # Discoverable credential flow (passkeys) - no allow_credentials needed
        []
      end

    {:ok, challenge} =
      WebAuthn.Actions.authentication_challenge(strategy, allow_credentials, tenant)

    response = %{
      challenge: Base.url_encode64(challenge.bytes, padding: false),
      rpId: WebAuthn.Helpers.resolve_rp_id(strategy, tenant),
      userVerification: strategy.user_verification,
      timeout: strategy.timeout,
      allowCredentials:
        Enum.map(allow_credentials, fn {cred_id, _key} ->
          %{id: Base.url_encode64(cred_id, padding: false), type: "public-key"}
        end)
    }

    # Store challenge as serializable map
    challenge_data = %{
      bytes: Base.encode64(challenge.bytes),
      type: challenge.type,
      origin: challenge.origin,
      rp_id: challenge.rp_id,
      allow_credentials:
        Enum.map(allow_credentials, fn {cred_id, cose_key} ->
          {Base.encode64(cred_id), cose_key}
        end),
      issued_at: challenge.issued_at
    }

    conn
    |> Conn.put_session(@session_key, challenge_data)
    |> Conn.put_resp_content_type("application/json")
    |> Conn.send_resp(200, Jason.encode!(response))
  end

  @doc "Handle an authentication request."
  @spec sign_in(Conn.t(), WebAuthn.t()) :: Conn.t()
  def sign_in(conn, strategy) do
    case reconstruct_challenge(conn, :authentication, strategy) do
      nil ->
        conn
        |> Conn.delete_session(@session_key)
        |> store_authentication_result(missing_challenge_error(strategy, :sign_in))

      challenge ->
        conn = Conn.delete_session(conn, @session_key)
        params = subject_params(conn, strategy)
        opts = opts(conn) ++ [challenge: challenge]
        result = Strategy.action(strategy, :sign_in, params, opts)
        store_authentication_result(conn, result)
    end
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

  # Reconstruct a Wax.Challenge from the serialized session data.
  # We store challenges as plain maps because cookie session stores
  # cannot serialize arbitrary Elixir structs.
  defp reconstruct_challenge(conn, type, strategy) do
    with %{} = data <- Conn.get_session(conn, @session_key),
         {:ok, bytes} <- Base.decode64(data["bytes"] || data[:bytes]) do
      build_challenge(data, bytes, type, strategy)
    else
      _ -> nil
    end
  end

  defp build_challenge(data, bytes, type, strategy) do
    base = %Wax.Challenge{
      type: type,
      bytes: bytes,
      origin: data["origin"] || data[:origin],
      rp_id: data["rp_id"] || data[:rp_id],
      issued_at: data["issued_at"] || data[:issued_at],
      origin_verify_fun: {Wax, :origins_match?, []}
    }

    case type do
      :attestation ->
        %{
          base
          | attestation: strategy.attestation,
            trusted_attestation_types: [:none, :basic, :self, :uncertain],
            verify_trust_root: false
        }

      _ ->
        %{base | allow_credentials: decode_allow_credentials(data)}
    end
  end

  defp decode_allow_credentials(data) do
    (data["allow_credentials"] || data[:allow_credentials] || [])
    |> Enum.flat_map(fn {encoded_id, cose_key} ->
      case Base.decode64(encoded_id) do
        {:ok, decoded_id} -> [{decoded_id, cose_key}]
        :error -> []
      end
    end)
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
      user
      |> Map.get(strategy.credentials_relationship_name, [])
      |> Enum.map(fn cred ->
        {Map.get(cred, strategy.credential_id_field), Map.get(cred, strategy.public_key_field)}
      end)
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
