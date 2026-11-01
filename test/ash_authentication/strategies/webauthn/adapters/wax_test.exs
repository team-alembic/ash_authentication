# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.Adapters.WaxTest do
  @moduledoc """
  The Wax adapter's own contract: every behaviour callback, driven directly.
  The ceremonies it verifies end to end are covered by the strategy tests,
  which run against it as the default adapter.
  """
  use ExUnit.Case, async: true

  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Strategy.WebAuthn.Adapters.Wax, as: Adapter
  alias AshAuthentication.Test.WebAuthnFixtures

  @moduletag feature: :webauthn

  @rp_id "example.com"

  defp strategy(overrides \\ []) do
    struct!(
      %WebAuthn{
        name: :webauthn,
        resource: __MODULE__,
        rp_id: @rp_id,
        rp_name: "Test",
        origin: "https://example.com"
      },
      overrides
    )
  end

  describe "check_dependencies/0" do
    test "reports wax_ as available when it is loaded" do
      assert :ok = Adapter.check_dependencies()
    end
  end

  describe "pub_key_cred_params/0" do
    test "lists the algorithms Wax can verify, in preference order" do
      algs = Enum.map(Adapter.pub_key_cred_params(), & &1.alg)

      assert [-7, -8 | _] = algs
      assert -257 in algs
      assert Enum.all?(Adapter.pub_key_cred_params(), &(&1.type == "public-key"))
      # Supported by Wax but deliberately not advertised: SHA-1 RSA, ES256K
      refute -65_535 in algs
      refute -47 in algs
    end
  end

  describe "registration_challenge/3" do
    test "builds an attestation challenge from the strategy's settings" do
      strategy =
        strategy(
          user_verification: "required",
          attestation: "direct",
          trusted_attestation_types: [:basic],
          verify_trust_root?: true,
          timeout: 120_001
        )

      challenge = Adapter.registration_challenge(strategy, nil, [])

      assert %Wax.Challenge{type: :attestation} = challenge
      assert byte_size(challenge.bytes) == 32
      assert challenge.rp_id == @rp_id
      assert challenge.origin == "https://example.com"
      assert challenge.user_verification == "required"
      assert challenge.attestation == "direct"
      assert challenge.trusted_attestation_types == [:basic]
      assert challenge.verify_trust_root == true
      # The DSL's milliseconds, as Wax's seconds, rounded up
      assert challenge.timeout == 121
    end

    test "resolves the relying party per tenant" do
      strategy =
        strategy(
          rp_id: fn tenant -> "#{tenant}.example.com" end,
          origin: nil
        )

      challenge = Adapter.registration_challenge(strategy, "acme", [])

      assert challenge.rp_id == "acme.example.com"
      assert challenge.origin == "https://acme.example.com"
    end

    test "every challenge gets fresh bytes" do
      refute Adapter.registration_challenge(strategy(), nil, []).bytes ==
               Adapter.registration_challenge(strategy(), nil, []).bytes
    end
  end

  describe "authentication_challenge/4" do
    test "builds an assertion challenge carrying the allowed credentials" do
      credentials = [{"cred-id", %{1 => 2}}]
      challenge = Adapter.authentication_challenge(strategy(), credentials, nil, [])

      assert %Wax.Challenge{type: :authentication} = challenge
      assert challenge.allow_credentials == credentials
      assert challenge.rp_id == @rp_id
      assert challenge.timeout == 60
    end
  end

  describe "challenge_bytes/1" do
    test "returns the random bytes the client must sign" do
      challenge = Adapter.registration_challenge(strategy(), nil, [])
      assert Adapter.challenge_bytes(challenge) == challenge.bytes
    end
  end

  describe "serialize_challenge/1 and deserialize_challenge/3" do
    test "an attestation challenge survives the round trip as plain values" do
      strategy = strategy(user_verification: "required", timeout: 300_000)
      challenge = Adapter.registration_challenge(strategy, nil, [])

      data = Adapter.serialize_challenge(challenge)
      assert plain?(data)
      refute Map.has_key?(data, :allow_credentials)

      restored = Adapter.deserialize_challenge(strategy, data, :attestation)

      assert %Wax.Challenge{type: :attestation} = restored
      assert restored.bytes == challenge.bytes
      assert restored.origin == challenge.origin
      assert restored.rp_id == challenge.rp_id
      assert restored.issued_at == challenge.issued_at
      assert restored.attestation == challenge.attestation
      assert restored.trusted_attestation_types == challenge.trusted_attestation_types
      assert restored.verify_trust_root == challenge.verify_trust_root
      assert restored.origin_verify_fun == {Wax, :origins_match?, []}
    end

    test "the rebuilt challenge takes user_verification and timeout from the strategy" do
      # Those two aren't serialized: Wax's struct defaults would otherwise
      # silently replace the strategy's settings.
      issued = strategy()
      challenge = Adapter.registration_challenge(issued, nil, [])
      data = Adapter.serialize_challenge(challenge)

      verifying = strategy(user_verification: "required", timeout: 300_000)
      restored = Adapter.deserialize_challenge(verifying, data, :attestation)

      assert restored.user_verification == "required"
      assert restored.timeout == 300
    end

    test "an authentication challenge keeps its credentials through the round trip" do
      credentials = [{<<1, 2, 3>>, %{1 => 2, 3 => -7}}, {<<4, 5>>, %{1 => 2}}]
      challenge = Adapter.authentication_challenge(strategy(), credentials, nil, [])

      data = Adapter.serialize_challenge(challenge)
      assert plain?(data)

      restored = Adapter.deserialize_challenge(strategy(), data, :authentication)
      assert %Wax.Challenge{type: :authentication} = restored
      assert restored.allow_credentials == credentials
    end

    test "accepts string keys, as a JSON session store produces" do
      challenge = Adapter.registration_challenge(strategy(), nil, [])

      data =
        challenge
        |> Adapter.serialize_challenge()
        |> Map.new(fn {key, value} -> {to_string(key), value} end)

      restored = Adapter.deserialize_challenge(strategy(), data, :attestation)
      assert restored.bytes == challenge.bytes
    end

    test "malformed data yields nil" do
      assert is_nil(
               Adapter.deserialize_challenge(strategy(), %{bytes: "not base64!"}, :attestation)
             )

      assert is_nil(Adapter.deserialize_challenge(strategy(), %{}, :attestation))
      assert is_nil(Adapter.deserialize_challenge(strategy(), nil, :attestation))
      assert is_nil(Adapter.deserialize_challenge(strategy(), "nope", :authentication))
    end
  end

  describe "verify_registration/4" do
    test "accepts a valid attestation and normalizes the result" do
      strategy = strategy()
      challenge = Adapter.registration_challenge(strategy, nil, [])

      fixture =
        WebAuthnFixtures.generate_registration(
          origin: "https://example.com",
          rp_id: @rp_id,
          challenge_bytes: challenge.bytes,
          # UP | BE | BS | AT
          flags: 0x59
        )

      assert {:ok, registration} =
               Adapter.verify_registration(
                 strategy,
                 decode(fixture.attestation_object),
                 decode(fixture.client_data_json),
                 challenge
               )

      assert registration.credential_id == fixture.credential_id
      assert registration.public_key == fixture.cose_key
      assert registration.sign_count == 0
      assert registration.backup_eligible == true
      assert registration.backed_up == true
    end

    test "rejects an attestation for another challenge" do
      strategy = strategy()
      challenge = Adapter.registration_challenge(strategy, nil, [])

      fixture =
        WebAuthnFixtures.generate_registration(origin: "https://example.com", rp_id: @rp_id)

      assert {:error, _} =
               Adapter.verify_registration(
                 strategy,
                 decode(fixture.attestation_object),
                 decode(fixture.client_data_json),
                 challenge
               )
    end

    test "rejects an attestation from an unexpected origin" do
      strategy = strategy()
      challenge = Adapter.registration_challenge(strategy, nil, [])

      fixture =
        WebAuthnFixtures.generate_registration(
          origin: "https://evil.example.org",
          rp_id: @rp_id,
          challenge_bytes: challenge.bytes
        )

      assert {:error, _} =
               Adapter.verify_registration(
                 strategy,
                 decode(fixture.attestation_object),
                 decode(fixture.client_data_json),
                 challenge
               )
    end
  end

  describe "verify_authentication/7" do
    setup do
      registration =
        WebAuthnFixtures.generate_registration(origin: "https://example.com", rp_id: @rp_id)

      %{
        registration: registration,
        credentials: [{registration.credential_id, registration.cose_key}]
      }
    end

    test "accepts a valid assertion and normalizes the result", %{
      registration: registration,
      credentials: credentials
    } do
      strategy = strategy()
      challenge = Adapter.authentication_challenge(strategy, [], nil, [])

      assertion =
        WebAuthnFixtures.generate_authentication(registration,
          challenge_bytes: challenge.bytes,
          sign_count: 9,
          # UP | UV | BE | BS
          flags: 0x1D
        )

      assert {:ok, %{sign_count: 9, backed_up: true}} =
               Adapter.verify_authentication(
                 strategy,
                 registration.credential_id,
                 decode(assertion.authenticator_data),
                 decode(assertion.signature),
                 decode(assertion.client_data_json),
                 challenge,
                 credentials
               )
    end

    test "rejects a signature made with another key", %{
      registration: registration,
      credentials: credentials
    } do
      strategy = strategy()
      challenge = Adapter.authentication_challenge(strategy, [], nil, [])

      other = WebAuthnFixtures.generate_registration(origin: "https://example.com", rp_id: @rp_id)

      forged =
        WebAuthnFixtures.generate_authentication(other, challenge_bytes: challenge.bytes)

      assert {:error, _} =
               Adapter.verify_authentication(
                 strategy,
                 registration.credential_id,
                 decode(forged.authenticator_data),
                 decode(forged.signature),
                 decode(forged.client_data_json),
                 challenge,
                 credentials
               )
    end

    test "rejects an assertion for an unknown credential", %{registration: registration} do
      strategy = strategy()
      challenge = Adapter.authentication_challenge(strategy, [], nil, [])

      assertion =
        WebAuthnFixtures.generate_authentication(registration, challenge_bytes: challenge.bytes)

      assert {:error, _} =
               Adapter.verify_authentication(
                 strategy,
                 registration.credential_id,
                 decode(assertion.authenticator_data),
                 decode(assertion.signature),
                 decode(assertion.client_data_json),
                 challenge,
                 []
               )
    end

    test "rejects an assertion without the UV flag when user verification is required", %{
      registration: registration,
      credentials: credentials
    } do
      strategy = strategy(user_verification: "required")
      challenge = Adapter.authentication_challenge(strategy, [], nil, [])

      assertion =
        WebAuthnFixtures.generate_authentication(registration,
          challenge_bytes: challenge.bytes,
          # UP only
          flags: 0x01
        )

      assert {:error, _} =
               Adapter.verify_authentication(
                 strategy,
                 registration.credential_id,
                 decode(assertion.authenticator_data),
                 decode(assertion.signature),
                 decode(assertion.client_data_json),
                 challenge,
                 credentials
               )
    end

    test "rejects an assertion once the challenge has expired", %{
      registration: registration,
      credentials: credentials
    } do
      strategy = strategy(timeout: 30_000)
      challenge = Adapter.authentication_challenge(strategy, [], nil, [])
      stale = %{challenge | issued_at: challenge.issued_at - 31}

      assertion =
        WebAuthnFixtures.generate_authentication(registration, challenge_bytes: challenge.bytes)

      assert {:error, %Wax.ExpiredChallengeError{}} =
               Adapter.verify_authentication(
                 strategy,
                 registration.credential_id,
                 decode(assertion.authenticator_data),
                 decode(assertion.signature),
                 decode(assertion.client_data_json),
                 stale,
                 credentials
               )
    end
  end

  defp decode(value), do: Base.url_decode64!(value, padding: false)

  # Session-safe: no structs, tuples only inside the credential list.
  defp plain?(%_{}), do: false
  defp plain?(map) when is_map(map), do: Enum.all?(map, fn {_k, v} -> plain?(v) end)
  defp plain?(list) when is_list(list), do: Enum.all?(list, &plain?/1)
  defp plain?({id, key}) when is_binary(id), do: plain?(key)
  defp plain?(value), do: is_binary(value) or is_number(value) or is_atom(value)
end
