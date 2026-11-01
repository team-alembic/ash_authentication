# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.AttestationTrustTest do
  @moduledoc """
  Registration with a real attestation statement — `"packed"` with a
  certificate chain, as a hardware security key sends it — under the
  attestation settings:

  - `attestation`: what the client is asked to convey;
  - `trusted_attestation_types`: which attestation types are accepted;
  - `verify_trust_root?`: whether the certificate chain must lead to a root
    in FIDO metadata.

  The fixture's authenticator is unknown to FIDO metadata, so its
  attestation can be verified but not trusted: Wax types it `:uncertain`.
  """
  use DataCase, async: false

  alias AshAuthentication.Errors.AuthenticationFailed
  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.WebAuthn.Actions
  alias AshAuthentication.Test.{WebAuthnAttestationFixtures, WebAuthnCeremony}

  @moduletag feature: :webauthn

  setup do
    %{strategy: Info.strategy!(Example.UserWithWebAuthn, :webauthn)}
  end

  for conveyance <- ["direct", "indirect", "enterprise"] do
    test "attestation #{inspect(conveyance)} verifies a packed statement and accepts it as :uncertain",
         %{strategy: strategy} do
      strategy = %{strategy | attestation: unquote(conveyance)}

      assert {:ok, user} = register_packed(strategy, "packed-#{unquote(conveyance)}@example.com")
      assert {:ok, [_credential]} = Actions.list_credentials(strategy, user, [])
    end
  end

  test "trusted_attestation_types without :uncertain refuses an unknown authenticator", %{
    strategy: strategy
  } do
    strategy = %{strategy | attestation: "direct", trusted_attestation_types: [:basic, :attca]}

    assert {:error, %AuthenticationFailed{} = error} =
             register_packed(strategy, "packed-untrusted@example.com")

    # `:uncertain` is what Wax assigns a verified packed chain it has no
    # metadata for; a "none" statement would be refused as `:none`.
    assert error.caused_by.message =~ "UntrustedAttestationType"
    assert error.caused_by.message =~ "type: :uncertain"
  end

  test "verify_trust_root? true refuses a chain with no root in FIDO metadata", %{
    strategy: strategy
  } do
    strategy = %{strategy | attestation: "direct", verify_trust_root?: true}

    assert {:error, %AuthenticationFailed{}} =
             register_packed(strategy, "packed-no-root@example.com")
  end

  test "a tampered statement signature is refused whatever the trust settings", %{
    strategy: strategy
  } do
    strategy = %{strategy | attestation: "direct"}
    {:ok, challenge} = Actions.registration_challenge(strategy, nil)
    {rp_id, origin} = WebAuthnCeremony.relying_party(strategy)

    # Signed over a different challenge than the one the client data carries.
    packed =
      WebAuthnAttestationFixtures.generate_packed_registration(
        rp_id: rp_id,
        origin: origin,
        challenge_bytes: strategy.adapter.challenge_bytes(challenge)
      )

    other =
      WebAuthnAttestationFixtures.generate_packed_registration(rp_id: rp_id, origin: origin)

    params = %{
      "email" => "packed-tampered@example.com",
      "attestation_object" => other.attestation_object,
      "client_data_json" => packed.client_data_json,
      "raw_id" => packed.raw_id
    }

    assert {:error, %AuthenticationFailed{}} =
             Actions.register(strategy, params, challenge: challenge)
  end

  defp register_packed(strategy, email) do
    {:ok, challenge} = Actions.registration_challenge(strategy, nil)
    {rp_id, origin} = WebAuthnCeremony.relying_party(strategy)

    passkey =
      WebAuthnAttestationFixtures.generate_packed_registration(
        rp_id: rp_id,
        origin: origin,
        challenge_bytes: strategy.adapter.challenge_bytes(challenge)
      )

    Actions.register(
      strategy,
      %{
        "email" => email,
        "attestation_object" => passkey.attestation_object,
        "client_data_json" => passkey.client_data_json,
        "raw_id" => passkey.raw_id
      },
      challenge: challenge
    )
  end
end
