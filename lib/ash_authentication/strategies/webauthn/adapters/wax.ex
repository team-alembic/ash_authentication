# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

if Code.ensure_loaded?(Wax) do
  defmodule AshAuthentication.Strategy.WebAuthn.Adapters.Wax do
    @moduledoc """
    The default WebAuthn adapter, backed by the optional `wax_` dependency.
    """

    alias AshAuthentication.Strategy.WebAuthn.{Adapter, Helpers}

    @behaviour Adapter

    @impl Adapter
    def registration_challenge(strategy, tenant, opts) do
      strategy
      |> Helpers.wax_opts(tenant, opts)
      |> Wax.new_registration_challenge()
    end

    @impl Adapter
    def authentication_challenge(strategy, allow_credentials, tenant, opts) do
      strategy
      |> Helpers.wax_opts(tenant, opts)
      |> Keyword.put(:allow_credentials, allow_credentials)
      |> Wax.new_authentication_challenge()
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

    @impl Adapter
    def deserialize_challenge(strategy, data, type) when is_map(data) do
      case Base.decode64(data["bytes"] || data[:bytes] || "") do
        {:ok, bytes} -> build_challenge(strategy, data, bytes, type)
        :error -> nil
      end
    end

    def deserialize_challenge(_strategy, _data, _type), do: nil

    # When reconstructing from session data the origin check must accept the
    # origin recorded at challenge time; `Wax.origins_match?/2` performs the
    # exact comparison.
    defp build_challenge(strategy, data, bytes, type) do
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

    The `:wax_` dependency is not present, so every callback returns an
    error. The strategy's own missing-dependency handling reports this before
    the adapter is ever reached.
    """

    @behaviour AshAuthentication.Strategy.WebAuthn.Adapter

    @error {:error, "The WebAuthn strategy requires the optional `:wax_` dependency"}

    @impl true
    def registration_challenge(_strategy, _tenant, _opts), do: @error
    @impl true
    def authentication_challenge(_strategy, _allow_credentials, _tenant, _opts), do: @error
    @impl true
    def challenge_bytes(_challenge), do: <<>>
    @impl true
    def serialize_challenge(_challenge), do: %{}
    @impl true
    def deserialize_challenge(_strategy, _data, _type), do: nil
    @impl true
    def verify_registration(_strategy, _attestation_object, _client_data_json, _challenge),
      do: @error

    @impl true
    def verify_authentication(
          _strategy,
          _credential_id,
          _authenticator_data,
          _signature,
          _client_data_json,
          _challenge,
          _allow_credentials
        ),
        do: @error
  end
end
