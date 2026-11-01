# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Test.WebAuthnMockAdapter do
  @moduledoc """
  A complete `AshAuthentication.Strategy.WebAuthn.Adapter` with no
  cryptographic backend at all, so the strategy can be driven end to end
  without Wax (or any other library) in the loop.

  The mock speaks its own, deliberately simple, wire format:

  * **Authenticator data** is JSON — `rp_id`, the `up`/`uv`/`be`/`bs` flags
    and the `sign_count` — rather than the spec's packed binary.
  * **Client data** is the spec's `clientDataJSON` (type, challenge, origin),
    because that part is the protocol, not the backend, and it is what the
    origin policy is checked against.
  * A credential is a random id plus a random 32-byte key. Its stored
    "public key" is a COSE symmetric key (`kty` 4, `alg` 5 = HMAC-256/256,
    `k` = the key), which the credential resource's `CoseKey` type encodes
    like any other COSE map.
  * **Signatures** — attestation and assertion alike — are
    `HMAC-SHA256(key, authenticator_data <> SHA256(client_data_json))`,
    the same construction the spec signs, so a response made with another
    key, for another challenge, or from another origin is rejected and a
    well-formed one is accepted. Nothing is stubbed: every check an adapter
    is responsible for runs, over the adapter's own challenge term.

  Challenges are `t:Challenge.t/0` structs, serialized to a string-keyed
  map (as a JSON session store would hand back), with `user_verification`
  and `timeout` re-derived from the strategy on rebuild, like the Wax
  adapter does.

  The `attestation/3` and `assertion/3` helpers play the authenticator for
  tests.
  """

  alias AshAuthentication.Strategy.WebAuthn.{Adapter, Helpers, Origin}

  @behaviour Adapter

  # COSE: kty 4 (Symmetric), alg 5 (HMAC 256/256), k at label -1.
  @kty_symmetric 4
  @alg_hmac_256 5
  @key_label -1

  @pub_key_cred_params [%{type: "public-key", alg: @alg_hmac_256}]

  defmodule Challenge do
    @moduledoc false
    @enforce_keys [
      :type,
      :bytes,
      :rp_id,
      :origin_policy,
      :issued_at,
      :timeout,
      :user_verification
    ]
    defstruct @enforce_keys ++ [allow_credentials: []]

    @type t :: %__MODULE__{
            type: :attestation | :authentication,
            bytes: binary,
            rp_id: String.t(),
            origin_policy: AshAuthentication.Strategy.WebAuthn.Origin.policy() | map,
            issued_at: integer,
            timeout: pos_integer,
            user_verification: String.t(),
            allow_credentials: Adapter.allow_credentials()
          }
  end

  @impl Adapter
  def check_dependencies, do: :ok

  @impl Adapter
  def pub_key_cred_params, do: @pub_key_cred_params

  @impl Adapter
  def registration_challenge(strategy, tenant, _opts) do
    new_challenge(strategy, tenant, :attestation, [])
  end

  @impl Adapter
  def authentication_challenge(strategy, allow_credentials, tenant, _opts) do
    new_challenge(strategy, tenant, :authentication, allow_credentials)
  end

  defp new_challenge(strategy, tenant, type, allow_credentials) do
    %Challenge{
      type: type,
      bytes: :crypto.strong_rand_bytes(32),
      rp_id: Helpers.resolve_rp_id(strategy, tenant),
      origin_policy: Origin.policy(strategy, tenant),
      issued_at: System.system_time(:second),
      timeout: Helpers.challenge_timeout_seconds(strategy),
      user_verification: strategy.user_verification,
      allow_credentials: allow_credentials
    }
  end

  @impl Adapter
  def challenge_bytes(%Challenge{bytes: bytes}), do: bytes

  @impl Adapter
  def serialize_challenge(%Challenge{} = challenge) do
    %{
      "mock" => true,
      "type" => Atom.to_string(challenge.type),
      "bytes" => Base.encode64(challenge.bytes),
      "rp_id" => challenge.rp_id,
      "origin" => Map.new(challenge.origin_policy, fn {k, v} -> {to_string(k), v} end),
      "issued_at" => challenge.issued_at,
      "allow_credentials" =>
        Enum.map(challenge.allow_credentials, fn {id, key} ->
          [Base.encode64(id), encode_cose_key(key)]
        end)
    }
  end

  @impl Adapter
  def deserialize_challenge(strategy, %{"mock" => true} = data, type) do
    with {:ok, bytes} when bytes != <<>> <- Base.decode64(data["bytes"] || ""),
         rp_id when is_binary(rp_id) <- data["rp_id"],
         issued_at when is_integer(issued_at) <- data["issued_at"],
         origin_policy when is_map(origin_policy) <- data["origin"],
         true <- Atom.to_string(type) == data["type"] do
      %Challenge{
        type: type,
        bytes: bytes,
        rp_id: rp_id,
        origin_policy: origin_policy,
        issued_at: issued_at,
        timeout: Helpers.challenge_timeout_seconds(strategy),
        user_verification: strategy.user_verification,
        allow_credentials:
          Enum.map(data["allow_credentials"] || [], fn [id, key] ->
            {Base.decode64!(id), decode_cose_key(key)}
          end)
      }
    else
      _ -> nil
    end
  end

  def deserialize_challenge(_strategy, _data, _type), do: nil

  @impl Adapter
  def verify_registration(
        _strategy,
        attestation_object,
        client_data_json,
        %Challenge{type: :attestation} = challenge
      ) do
    with :ok <- not_expired(challenge),
         {:ok, attestation} <- decode_json(attestation_object, :invalid_attestation_object),
         %{"auth_data" => auth_data_json, "credential_id" => id, "key" => key, "mac" => mac} <-
           attestation,
         {:ok, credential_id} <- decode_b64(id),
         {:ok, key} <- decode_b64(key),
         {:ok, mac} <- decode_b64(mac),
         :ok <- check_client_data(client_data_json, "webauthn.create", challenge),
         {:ok, auth_data} <- decode_auth_data(auth_data_json, challenge),
         :ok <- check_mac(key, auth_data_json, client_data_json, mac) do
      {:ok,
       %{
         credential_id: credential_id,
         public_key: cose_key(key),
         sign_count: auth_data["sign_count"],
         backup_eligible: auth_data["be"],
         backed_up: auth_data["bs"]
       }}
    else
      %{} -> {:error, :invalid_attestation_object}
      {:error, _} = error -> error
    end
  end

  def verify_registration(_strategy, _attestation_object, _client_data_json, _challenge),
    do: {:error, :not_an_attestation_challenge}

  @impl Adapter
  def verify_authentication(
        _strategy,
        credential_id,
        authenticator_data,
        signature,
        client_data_json,
        %Challenge{type: :authentication} = challenge,
        allow_credentials
      ) do
    with :ok <- not_expired(challenge),
         {:ok, key} <- key_for(credential_id, challenge, allow_credentials),
         :ok <- check_client_data(client_data_json, "webauthn.get", challenge),
         {:ok, auth_data} <- decode_auth_data(authenticator_data, challenge),
         :ok <- check_mac(key, authenticator_data, client_data_json, signature) do
      {:ok, %{sign_count: auth_data["sign_count"], backed_up: auth_data["bs"]}}
    end
  end

  def verify_authentication(_strategy, _id, _auth_data, _sig, _client_data, _challenge, _creds),
    do: {:error, :not_an_authentication_challenge}

  # --- verification steps -------------------------------------------------

  defp not_expired(%Challenge{issued_at: issued_at, timeout: timeout}) do
    if System.system_time(:second) - issued_at < timeout,
      do: :ok,
      else: {:error, :challenge_expired}
  end

  # The credential must be among those the strategy looked up for this
  # assertion and, when the challenge named credentials (the second-factor
  # verify lists the actor's), among those too.
  defp key_for(credential_id, %Challenge{allow_credentials: listed}, allow_credentials) do
    with {_, %{} = cose_key} <- List.keyfind(allow_credentials, credential_id, 0),
         true <- listed == [] or List.keymember?(listed, credential_id, 0),
         key when is_binary(key) <- cose_key[@key_label] do
      {:ok, key}
    else
      _ -> {:error, :unknown_credential}
    end
  end

  defp check_client_data(client_data_json, expected_type, challenge) do
    with {:ok, client_data} <- decode_json(client_data_json, :invalid_client_data),
         %{"type" => ^expected_type} <- client_data,
         {:ok, bytes} <- Base.url_decode64(client_data["challenge"] || "", padding: false),
         true <- bytes == challenge.bytes do
      if Origin.allowed?(client_data["origin"], challenge.origin_policy),
        do: :ok,
        else: {:error, :origin_mismatch}
    else
      %{"type" => _} -> {:error, :wrong_ceremony_type}
      {:error, _} = error -> error
      _ -> {:error, :challenge_mismatch}
    end
  end

  defp decode_auth_data(auth_data_json, challenge) do
    with {:ok, auth_data} <- decode_json(auth_data_json, :invalid_authenticator_data),
         true <- auth_data["rp_id"] == challenge.rp_id || {:error, :rp_id_mismatch},
         true <- auth_data["up"] == true || {:error, :user_not_present},
         true <-
           (challenge.user_verification != "required" or auth_data["uv"] == true) ||
             {:error, :user_not_verified} do
      {:ok, auth_data}
    else
      {:error, _} = error -> error
    end
  end

  defp check_mac(key, authenticator_data, client_data_json, mac) do
    if Plug.Crypto.secure_compare(sign(key, authenticator_data, client_data_json), mac),
      do: :ok,
      else: {:error, :invalid_signature}
  end

  defp sign(key, authenticator_data, client_data_json) do
    :crypto.mac(
      :hmac,
      :sha256,
      key,
      authenticator_data <> :crypto.hash(:sha256, client_data_json)
    )
  end

  defp cose_key(key), do: %{1 => @kty_symmetric, 3 => @alg_hmac_256, @key_label => key}

  defp decode_json(binary, error) when is_binary(binary) do
    case Jason.decode(binary) do
      {:ok, %{} = decoded} -> {:ok, decoded}
      _ -> {:error, error}
    end
  end

  defp decode_json(_other, error), do: {:error, error}

  defp decode_b64(value) when is_binary(value) do
    case Base.url_decode64(value, padding: false) do
      {:ok, _} = ok -> ok
      :error -> {:error, :invalid_encoding}
    end
  end

  defp decode_b64(_value), do: {:error, :invalid_encoding}

  # COSE maps have integer labels and binary key material; neither survives
  # a JSON session store as is.
  defp encode_cose_key(cose_key) do
    Map.new(cose_key, fn {k, v} ->
      {to_string(k), if(is_binary(v), do: Base.encode64(v), else: v)}
    end)
  end

  defp decode_cose_key(encoded) do
    Map.new(encoded, fn {k, v} ->
      {String.to_integer(k), if(is_binary(v), do: Base.decode64!(v), else: v)}
    end)
  end

  # --- the authenticator's side -------------------------------------------

  @doc "A fresh mock authenticator credential: a random id and signing key."
  @spec new_credential() :: %{credential_id: binary, key: binary}
  def new_credential,
    do: %{credential_id: :crypto.strong_rand_bytes(16), key: :crypto.strong_rand_bytes(32)}

  @doc "The COSE key the strategy stores for a mock credential."
  @spec public_key(%{key: binary}) :: map
  def public_key(%{key: key}), do: cose_key(key)

  @doc """
  Answer a registration challenge, as the browser's `navigator.credentials.create()`
  would, with the base64url-encoded params the strategy's actions expect.

  Options: `:origin` (default `"https://example.com"`), `:rp_id` (default
  `"example.com"`), `:up`/`:uv`/`:be`/`:bs` flags (default `true`, `true`,
  `false`, `false`), `:sign_count` (default `0`), `:key` to sign with another
  key than the credential's, `:type` to send another client data type.
  """
  @spec attestation(%{credential_id: binary, key: binary}, binary, keyword) :: %{
          String.t() => String.t()
        }
  def attestation(credential, challenge_bytes, opts \\ []) do
    auth_data = auth_data_json(opts, 0)

    client_data_json =
      client_data_json(Keyword.get(opts, :type, "webauthn.create"), challenge_bytes, opts)

    attestation_object =
      Jason.encode!(%{
        "auth_data" => auth_data,
        "credential_id" => url64(credential.credential_id),
        "key" => url64(credential.key),
        "mac" => url64(sign(Keyword.get(opts, :key, credential.key), auth_data, client_data_json))
      })

    %{
      "attestation_object" => url64(attestation_object),
      "client_data_json" => url64(client_data_json),
      "raw_id" => url64(credential.credential_id)
    }
  end

  @doc """
  Answer an authentication challenge, as `navigator.credentials.get()` would.

  Same options as `attestation/3`; `:sign_count` defaults to `1`, `:uv` to
  `true`. `:user_handle` adds the (base64url-encoded) handle the
  authenticator would return for a discoverable credential.
  """
  @spec assertion(%{credential_id: binary, key: binary}, binary, keyword) :: %{
          String.t() => String.t()
        }
  def assertion(credential, challenge_bytes, opts \\ []) do
    auth_data = auth_data_json(opts, 1)

    client_data_json =
      client_data_json(Keyword.get(opts, :type, "webauthn.get"), challenge_bytes, opts)

    params = %{
      "raw_id" => url64(credential.credential_id),
      "authenticator_data" => url64(auth_data),
      "signature" =>
        url64(sign(Keyword.get(opts, :key, credential.key), auth_data, client_data_json)),
      "client_data_json" => url64(client_data_json)
    }

    case Keyword.get(opts, :user_handle) do
      nil -> params
      handle -> Map.put(params, "user_handle", url64(handle))
    end
  end

  defp auth_data_json(opts, default_sign_count) do
    Jason.encode!(%{
      "rp_id" => Keyword.get(opts, :rp_id, "example.com"),
      "up" => Keyword.get(opts, :up, true),
      "uv" => Keyword.get(opts, :uv, true),
      "be" => Keyword.get(opts, :be, false),
      "bs" => Keyword.get(opts, :bs, false),
      "sign_count" => Keyword.get(opts, :sign_count, default_sign_count)
    })
  end

  defp client_data_json(type, challenge_bytes, opts) do
    Jason.encode!(%{
      "type" => type,
      "challenge" => url64(challenge_bytes),
      "origin" => Keyword.get(opts, :origin, "https://example.com"),
      "crossOrigin" => false
    })
  end

  defp url64(binary), do: Base.url_encode64(binary, padding: false)
end
