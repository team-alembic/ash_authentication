# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Wax) do
  defmodule AshAuthentication.Strategy.WebAuthn.Adapters.Wax do
    @moduledoc """
    The default WebAuthn adapter, backed by the optional `wax_` dependency.

    This module is the only place in the library that refers to Wax. Every
    strategy option Wax enforces is translated into a `Wax.Challenge` here:
    the relying party ID, the ceremony timeout, `user_verification`, the
    attestation settings, and the origin policy. The policy
    (`AshAuthentication.Strategy.WebAuthn.Origin`) rides in the challenge's
    `origin` field and is applied through Wax's `origin_verify_fun`, so the
    challenge rebuilt from the session enforces exactly what was issued.

    ## Attestation and FIDO metadata

    Verifying attestation trust roots (`verify_trust_root? true`, or
    `trusted_attestation_types` without `:none`/`:uncertain`) needs FIDO
    metadata, which Wax loads itself:

    ```elixir
    config :wax_, update_metadata: true
    ```

    or `config :wax_, metadata_dir: :my_app` to ship statements from
    `priv/fido2_metadata/`. See the `Wax` documentation.
    """

    alias AshAuthentication.Strategy.WebAuthn.{Adapter, Helpers, Origin}

    @behaviour Adapter

    # Wax calls this as `apply(m, f, [client_origin, challenge.origin])`,
    # which is `Origin.allowed?/2`'s argument order.
    @origin_verify_fun {Origin, :allowed?, []}

    # COSE algorithms Wax can verify, in preference order. Deliberately
    # excludes RSASSA-PKCS1-v1_5 w/ SHA-1 (-65535) and ES256K (-47).
    @pub_key_cred_params Enum.map(
                           [-7, -8, -35, -36, -37, -38, -39, -257, -258, -259],
                           &%{type: "public-key", alg: &1}
                         )

    @impl Adapter
    def check_dependencies, do: :ok

    @impl Adapter
    def pub_key_cred_params, do: @pub_key_cred_params

    @impl Adapter
    def registration_challenge(strategy, tenant, opts) do
      strategy
      |> challenge_opts(tenant, secret_context(opts))
      |> Wax.new_registration_challenge()
    end

    @impl Adapter
    def authentication_challenge(strategy, allow_credentials, tenant, opts) do
      strategy
      |> challenge_opts(tenant, secret_context(opts))
      |> Keyword.put(:allow_credentials, allow_credentials)
      |> Wax.new_authentication_challenge()
    end

    defp secret_context(opts), do: Keyword.get(opts, :context, %{})

    # The strategy's settings as Wax challenge options, with the dynamic
    # relying-party values resolved for the tenant, in the caller's context.
    # The DSL's `timeout` is in milliseconds; Wax counts a challenge's
    # validity in whole seconds.
    #
    # Wax's `origin` is typed as "a string, a list, or anything" because it
    # only ever hands it to `origin_verify_fun`; the strategy's origin policy
    # goes in as-is and the policy module does the comparison.
    defp challenge_opts(strategy, tenant, context) do
      [
        origin: Origin.policy(strategy, tenant, context),
        origin_verify_fun: @origin_verify_fun,
        rp_id: Helpers.resolve_rp_id(strategy, tenant, context),
        user_verification: strategy.user_verification,
        attestation: strategy.attestation,
        trusted_attestation_types: strategy.trusted_attestation_types,
        verify_trust_root: strategy.verify_trust_root?,
        timeout: Helpers.challenge_timeout_seconds(strategy)
      ]
    end

    @impl Adapter
    def challenge_bytes(%Wax.Challenge{bytes: bytes}), do: bytes

    # Challenges are stored as plain maps (not structs) so cookie session
    # stores can serialize them.
    @impl Adapter
    def serialize_challenge(%Wax.Challenge{} = challenge) do
      base = %{
        bytes: Base.encode64(challenge.bytes),
        type: challenge.type,
        origin: challenge.origin,
        rp_id: challenge.rp_id,
        issued_at: challenge.issued_at
      }

      case challenge.type do
        :authentication ->
          Map.put(
            base,
            :allow_credentials,
            Enum.map(challenge.allow_credentials, fn {cred_id, cose_key} ->
              {Base.encode64(cred_id), cose_key}
            end)
          )

        _ ->
          base
      end
    end

    # Everything Wax's verification reads has to be present and well-formed;
    # a half-built challenge (no bytes, no issue time) must not come back as
    # one the ceremony could be verified against.
    @impl Adapter
    def deserialize_challenge(strategy, data, type) when is_map(data) do
      with {:ok, bytes} when bytes != <<>> <- Base.decode64(data["bytes"] || data[:bytes] || ""),
           rp_id when is_binary(rp_id) <- data["rp_id"] || data[:rp_id],
           issued_at when is_integer(issued_at) <- data["issued_at"] || data[:issued_at] do
        build_challenge(strategy, data, bytes, rp_id, issued_at, type)
      else
        _ -> nil
      end
    end

    def deserialize_challenge(_strategy, _data, _type), do: nil

    # The origin policy recorded at challenge time comes back as the plain
    # map it was stored as (string-keyed if the session store went through
    # JSON); `Origin.allowed?/2` reads either form.
    #
    # The struct is built directly rather than through `Wax.Challenge.new/1`,
    # so every field Wax verifies against has to be set here: anything left
    # out silently takes the struct default instead of the strategy's
    # setting. In particular `user_verification` would fall back to
    # `"preferred"` (Wax then never checks the UV flag, so `"required"` would
    # only be a request to the browser) and `timeout` to 120 seconds (cutting
    # off any ceremony configured to last longer).
    defp build_challenge(strategy, data, bytes, rp_id, issued_at, type) do
      base = %Wax.Challenge{
        type: type,
        bytes: bytes,
        origin: data["origin"] || data[:origin],
        rp_id: rp_id,
        issued_at: issued_at,
        origin_verify_fun: @origin_verify_fun,
        user_verification: strategy.user_verification,
        timeout: Helpers.challenge_timeout_seconds(strategy)
      }

      case type do
        :attestation ->
          %{
            base
            | attestation: strategy.attestation,
              trusted_attestation_types: strategy.trusted_attestation_types,
              verify_trust_root: strategy.verify_trust_root?
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

    @impl Adapter
    def verify_registration(_strategy, attestation_object, client_data_json, challenge) do
      {attestation_object, challenge} = for_verification(attestation_object, challenge)

      case Wax.register(attestation_object, client_data_json, challenge) do
        {:ok, {auth_data, _attestation_result}} ->
          cred_data = auth_data.attested_credential_data

          {:ok,
           %{
             credential_id: cred_data.credential_id,
             public_key: cred_data.credential_public_key,
             sign_count: auth_data.sign_count,
             backup_eligible: auth_data.flag_backup_eligible,
             backed_up: auth_data.flag_credential_backed_up
           }}

        {:error, _} = error ->
          error
      end
    end

    # The strategy's `attestation` is the WebAuthn conveyance preference: what
    # the browser is *asked* to convey. Wax reads the same field as the one
    # statement format it will accept — a `"none"` statement only under
    # `"none"`, every other format only under `"direct"` — and has no notion of
    # `"indirect"` or `"enterprise"`.
    #
    # Whatever was requested, the client may answer with a `"none"` statement
    # (synced passkeys always do, and `"indirect"` lets the client strip it),
    # and under `"indirect"`/`"enterprise"` with a full one. So once anything
    # beyond `"none"` was requested, verify against the format the client
    # actually conveyed, and leave accepting or refusing the result to
    # `trusted_attestation_types` — where the strategy's documentation puts
    # attestation policy.
    #
    # Under `"none"` the relying party has said it doesn't want attestation,
    # and the client is supposed to replace any statement with a `"none"` one
    # (§5.4.7). Not every client does, and Wax refuses a real statement under
    # `"none"`, which would fail the registration over something nobody asked
    # for. So do the client's replacement here: keep the authenticator data,
    # which carries the credential and the RP ID hash, and drop the statement.
    defp for_verification(attestation_object, %Wax.Challenge{attestation: "none"} = challenge) do
      case CBOR.decode(attestation_object) do
        {:ok, %{"fmt" => fmt, "authData" => auth_data}, _rest} when fmt != "none" ->
          {none_statement(auth_data), challenge}

        _ ->
          {attestation_object, challenge}
      end
    end

    defp for_verification(attestation_object, %Wax.Challenge{} = challenge) do
      case CBOR.decode(attestation_object) do
        {:ok, %{"fmt" => "none"}, _rest} ->
          {attestation_object, %{challenge | attestation: "none"}}

        _ ->
          {attestation_object, %{challenge | attestation: "direct"}}
      end
    end

    defp none_statement(auth_data) do
      %{
        "fmt" => "none",
        "attStmt" => %{},
        "authData" => %CBOR.Tag{tag: :bytes, value: cbor_bytes(auth_data)}
      }
      |> CBOR.encode()
      |> IO.iodata_to_binary()
    end

    defp cbor_bytes(%CBOR.Tag{tag: :bytes, value: value}), do: value
    defp cbor_bytes(value) when is_binary(value), do: value

    @impl Adapter
    def verify_authentication(
          _strategy,
          credential_id,
          authenticator_data,
          signature,
          client_data_json,
          challenge,
          allow_credentials
        ) do
      case Wax.authenticate(
             credential_id,
             authenticator_data,
             signature,
             client_data_json,
             challenge,
             allow_credentials
           ) do
        {:ok, auth_data} ->
          {:ok,
           %{
             sign_count: auth_data.sign_count,
             backed_up: auth_data.flag_credential_backed_up
           }}

        {:error, _} = error ->
          error
      end
    end
  end
else
  defmodule AshAuthentication.Strategy.WebAuthn.Adapters.Wax do
    @moduledoc """
    The default WebAuthn adapter, backed by the optional `wax_` dependency.

    The `:wax_` dependency was not present when `ash_authentication` was
    compiled, so this adapter cannot run a ceremony. `check_dependencies/0`
    says so, which the strategy's verifier reports as a configuration error
    for any strategy that uses this adapter; the other callbacks refuse to
    do anything, so a strategy that somehow reaches them fails closed.
    """

    alias AshAuthentication.Strategy.WebAuthn.Adapter

    @behaviour Adapter

    @message """
    The WebAuthn strategy's default adapter requires the optional `:wax_` dependency.

    Add it to your dependencies:

        {:wax_, "~> 0.7"}

    If `ash_authentication` was already compiled without `:wax_`, recompile it:

        mix deps.compile ash_authentication --force

    Or configure a different `adapter` on the strategy.
    """

    @impl Adapter
    def check_dependencies, do: {:error, @message}

    @impl Adapter
    def pub_key_cred_params, do: []

    @impl Adapter
    def registration_challenge(_strategy, _tenant, _opts), do: raise(@message)

    @impl Adapter
    def authentication_challenge(_strategy, _allow_credentials, _tenant, _opts),
      do: raise(@message)

    @impl Adapter
    def challenge_bytes(_challenge), do: <<>>

    @impl Adapter
    def serialize_challenge(_challenge), do: %{}

    @impl Adapter
    def deserialize_challenge(_strategy, _data, _type), do: nil

    @impl Adapter
    def verify_registration(_strategy, _attestation_object, _client_data_json, _challenge),
      do: {:error, @message}

    @impl Adapter
    def verify_authentication(
          _strategy,
          _credential_id,
          _authenticator_data,
          _signature,
          _client_data_json,
          _challenge,
          _allow_credentials
        ),
        do: {:error, @message}
  end
end
