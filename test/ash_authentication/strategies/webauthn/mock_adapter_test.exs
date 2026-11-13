# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Test.WebAuthnMockAdapterTest do
  @moduledoc """
  The mock adapter's own contract, callback by callback. It has to accept a
  well-formed response and reject every broken one on its own, or the
  ceremony suite that runs on it proves nothing.
  """
  use ExUnit.Case, async: true

  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Strategy.WebAuthn.Origin
  alias AshAuthentication.Test.WebAuthnMockAdapter, as: Mock
  alias AshAuthentication.Test.WebAuthnMockAdapter.Challenge

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

  defp decode(value), do: Base.url_decode64!(value, padding: false)

  defp verify_registration(strategy, response, challenge) do
    Mock.verify_registration(
      strategy,
      decode(response["attestation_object"]),
      decode(response["client_data_json"]),
      challenge
    )
  end

  defp verify_authentication(strategy, credential, response, challenge, allow_credentials) do
    Mock.verify_authentication(
      strategy,
      credential.credential_id,
      decode(response["authenticator_data"]),
      decode(response["signature"]),
      decode(response["client_data_json"]),
      challenge,
      allow_credentials
    )
  end

  test "check_dependencies/0 needs nothing" do
    assert :ok = Mock.check_dependencies()
  end

  test "pub_key_cred_params/0 advertises its one (symmetric) algorithm" do
    assert [%{type: "public-key", alg: 5}] = Mock.pub_key_cred_params()
  end

  describe "registration_challenge/3" do
    test "builds an attestation challenge from the strategy's settings" do
      strategy = strategy(user_verification: "required", timeout: 120_001)
      challenge = Mock.registration_challenge(strategy, nil, [])

      assert %Challenge{type: :attestation, allow_credentials: []} = challenge
      assert byte_size(challenge.bytes) == 32
      assert challenge.rp_id == @rp_id
      assert challenge.origin_policy == %{allow: ["https://example.com"]}
      assert challenge.user_verification == "required"
      assert challenge.timeout == 121
      assert_in_delta challenge.issued_at, System.system_time(:second), 2
    end

    test "resolves the relying party and origin policy per tenant" do
      strategy = strategy(rp_id: fn t -> "#{t}.example.com" end, origin: nil)
      challenge = Mock.registration_challenge(strategy, "acme", [])

      assert challenge.rp_id == "acme.example.com"
      assert challenge.origin_policy == %{rp_id: "acme.example.com"}
    end

    test "every challenge gets fresh bytes" do
      refute Mock.registration_challenge(strategy(), nil, []).bytes ==
               Mock.registration_challenge(strategy(), nil, []).bytes
    end
  end

  describe "authentication_challenge/4" do
    test "builds an assertion challenge carrying the allowed credentials" do
      credential = Mock.new_credential()
      allowed = [{credential.credential_id, Mock.public_key(credential)}]
      challenge = Mock.authentication_challenge(strategy(), allowed, nil, [])

      assert %Challenge{type: :authentication} = challenge
      assert challenge.allow_credentials == allowed
    end
  end

  test "challenge_bytes/1 returns the bytes the client signs" do
    challenge = Mock.registration_challenge(strategy(), nil, [])
    assert Mock.challenge_bytes(challenge) == challenge.bytes
  end

  describe "serialize_challenge/1 and deserialize_challenge/3" do
    test "an attestation challenge survives the round trip as a string-keyed plain map" do
      strategy = strategy(origin: nil)
      challenge = Mock.registration_challenge(strategy, nil, [])
      data = Mock.serialize_challenge(challenge)

      assert Enum.all?(Map.keys(data), &is_binary/1)
      assert data["origin"] == %{"rp_id" => @rp_id}
      assert Jason.encode!(data)

      restored = Mock.deserialize_challenge(strategy, data, :attestation)
      assert %Challenge{type: :attestation} = restored
      assert restored.bytes == challenge.bytes
      assert restored.rp_id == challenge.rp_id
      assert restored.issued_at == challenge.issued_at
      assert restored.origin_policy == %{"rp_id" => @rp_id}
      assert Origin.allowed?("https://app.example.com", restored.origin_policy)
    end

    test "an authentication challenge keeps its credentials" do
      credential = Mock.new_credential()
      allowed = [{credential.credential_id, Mock.public_key(credential)}]
      challenge = Mock.authentication_challenge(strategy(), allowed, nil, [])

      data = Mock.serialize_challenge(challenge)
      assert Jason.encode!(data)

      restored = Mock.deserialize_challenge(strategy(), data, :authentication)
      assert restored.allow_credentials == allowed
    end

    test "user_verification and timeout come from the strategy on rebuild" do
      data = Mock.serialize_challenge(Mock.registration_challenge(strategy(), nil, []))
      verifying = strategy(user_verification: "required", timeout: 300_000)

      restored = Mock.deserialize_challenge(verifying, data, :attestation)
      assert restored.user_verification == "required"
      assert restored.timeout == 300
    end

    test "a challenge of the other type does not rebuild" do
      data = Mock.serialize_challenge(Mock.registration_challenge(strategy(), nil, []))
      assert is_nil(Mock.deserialize_challenge(strategy(), data, :authentication))
    end

    test "malformed or foreign data yields nil" do
      assert is_nil(Mock.deserialize_challenge(strategy(), %{}, :attestation))
      assert is_nil(Mock.deserialize_challenge(strategy(), %{"mock" => true}, :attestation))

      assert is_nil(
               Mock.deserialize_challenge(strategy(), %{bytes: "x", stub: true}, :attestation)
             )

      assert is_nil(Mock.deserialize_challenge(strategy(), nil, :attestation))

      data = Mock.serialize_challenge(Mock.registration_challenge(strategy(), nil, []))
      assert is_nil(Mock.deserialize_challenge(strategy(), %{data | "bytes" => ""}, :attestation))

      assert is_nil(
               Mock.deserialize_challenge(strategy(), Map.delete(data, "issued_at"), :attestation)
             )

      assert is_nil(
               Mock.deserialize_challenge(strategy(), Map.delete(data, "origin"), :attestation)
             )
    end
  end

  describe "verify_registration/4" do
    setup do
      strategy = strategy()

      %{
        strategy: strategy,
        credential: Mock.new_credential(),
        challenge: Mock.registration_challenge(strategy, nil, [])
      }
    end

    test "accepts a well-formed attestation and normalizes it", %{
      strategy: strategy,
      credential: credential,
      challenge: challenge
    } do
      response = Mock.attestation(credential, challenge.bytes, be: true, bs: true, sign_count: 3)

      assert {:ok, registration} = verify_registration(strategy, response, challenge)
      assert registration.credential_id == credential.credential_id
      assert registration.public_key == Mock.public_key(credential)
      assert registration.public_key == %{1 => 4, 3 => 5, -1 => credential.key}
      assert registration.sign_count == 3
      assert registration.backup_eligible == true
      assert registration.backed_up == true
    end

    test "rejects an attestation for another challenge", ctx do
      response = Mock.attestation(ctx.credential, :crypto.strong_rand_bytes(32))

      assert {:error, :challenge_mismatch} =
               verify_registration(ctx.strategy, response, ctx.challenge)
    end

    test "rejects an origin outside the policy", ctx do
      for origin <- ["https://evil.com", "https://app.example.com", "http://example.com"] do
        response = Mock.attestation(ctx.credential, ctx.challenge.bytes, origin: origin)

        assert {:error, :origin_mismatch} =
                 verify_registration(ctx.strategy, response, ctx.challenge)
      end
    end

    test "accepts any https origin under the rp_id when none is configured" do
      strategy = strategy(origin: nil)
      challenge = Mock.registration_challenge(strategy, nil, [])
      credential = Mock.new_credential()

      response =
        Mock.attestation(credential, challenge.bytes, origin: "https://app.example.com:4001")

      assert {:ok, _} = verify_registration(strategy, response, challenge)

      response = Mock.attestation(credential, challenge.bytes, origin: "http://app.example.com")
      assert {:error, :origin_mismatch} = verify_registration(strategy, response, challenge)
    end

    test "rejects another relying party", ctx do
      response = Mock.attestation(ctx.credential, ctx.challenge.bytes, rp_id: "evil.com")

      assert {:error, :rp_id_mismatch} =
               verify_registration(ctx.strategy, response, ctx.challenge)
    end

    test "rejects a MAC made with another key", ctx do
      response =
        Mock.attestation(ctx.credential, ctx.challenge.bytes, key: :crypto.strong_rand_bytes(32))

      assert {:error, :invalid_signature} =
               verify_registration(ctx.strategy, response, ctx.challenge)
    end

    test "rejects a tampered client data", ctx do
      response = Mock.attestation(ctx.credential, ctx.challenge.bytes)

      tampered =
        String.replace(
          decode(response["client_data_json"]),
          "crossOrigin\":false",
          "crossOrigin\":true"
        )

      assert {:error, :invalid_signature} =
               Mock.verify_registration(
                 ctx.strategy,
                 decode(response["attestation_object"]),
                 tampered,
                 ctx.challenge
               )
    end

    test "rejects an assertion-type client data", ctx do
      response = Mock.attestation(ctx.credential, ctx.challenge.bytes, type: "webauthn.get")

      assert {:error, :wrong_ceremony_type} =
               verify_registration(ctx.strategy, response, ctx.challenge)
    end

    test "requires user presence, and user verification when the strategy does", ctx do
      response = Mock.attestation(ctx.credential, ctx.challenge.bytes, up: false)

      assert {:error, :user_not_present} =
               verify_registration(ctx.strategy, response, ctx.challenge)

      response = Mock.attestation(ctx.credential, ctx.challenge.bytes, uv: false)
      assert {:ok, _} = verify_registration(ctx.strategy, response, ctx.challenge)

      required = %{ctx.challenge | user_verification: "required"}
      assert {:error, :user_not_verified} = verify_registration(ctx.strategy, response, required)
    end

    test "rejects an expired challenge", ctx do
      response = Mock.attestation(ctx.credential, ctx.challenge.bytes)
      stale = %{ctx.challenge | issued_at: ctx.challenge.issued_at - ctx.challenge.timeout}
      assert {:error, :challenge_expired} = verify_registration(ctx.strategy, response, stale)
    end

    test "rejects an authentication challenge and garbage", ctx do
      response = Mock.attestation(ctx.credential, ctx.challenge.bytes)
      auth_challenge = Mock.authentication_challenge(ctx.strategy, [], nil, [])

      assert {:error, :not_an_attestation_challenge} =
               verify_registration(ctx.strategy, response, auth_challenge)

      assert {:error, :invalid_attestation_object} =
               Mock.verify_registration(
                 ctx.strategy,
                 "not json",
                 decode(response["client_data_json"]),
                 ctx.challenge
               )

      assert {:error, :invalid_attestation_object} =
               Mock.verify_registration(
                 ctx.strategy,
                 "{}",
                 decode(response["client_data_json"]),
                 ctx.challenge
               )

      assert {:error, :invalid_client_data} =
               Mock.verify_registration(
                 ctx.strategy,
                 decode(response["attestation_object"]),
                 "nope",
                 ctx.challenge
               )
    end
  end

  describe "verify_authentication/7" do
    setup do
      strategy = strategy()
      credential = Mock.new_credential()

      %{
        strategy: strategy,
        credential: credential,
        allowed: [{credential.credential_id, Mock.public_key(credential)}],
        challenge: Mock.authentication_challenge(strategy, [], nil, [])
      }
    end

    test "accepts a well-formed assertion and normalizes it", ctx do
      response = Mock.assertion(ctx.credential, ctx.challenge.bytes, sign_count: 9, bs: true)

      assert {:ok, %{sign_count: 9, backed_up: true}} =
               verify_authentication(
                 ctx.strategy,
                 ctx.credential,
                 response,
                 ctx.challenge,
                 ctx.allowed
               )
    end

    test "rejects a signature made with another key", ctx do
      response =
        Mock.assertion(ctx.credential, ctx.challenge.bytes, key: :crypto.strong_rand_bytes(32))

      assert {:error, :invalid_signature} =
               verify_authentication(
                 ctx.strategy,
                 ctx.credential,
                 response,
                 ctx.challenge,
                 ctx.allowed
               )
    end

    test "rejects a credential the strategy didn't look up", ctx do
      response = Mock.assertion(ctx.credential, ctx.challenge.bytes)

      assert {:error, :unknown_credential} =
               verify_authentication(ctx.strategy, ctx.credential, response, ctx.challenge, [])
    end

    test "rejects a credential the challenge didn't list, when it listed any", ctx do
      other = Mock.new_credential()

      listed =
        Mock.authentication_challenge(
          ctx.strategy,
          [{other.credential_id, Mock.public_key(other)}],
          nil,
          []
        )

      response = Mock.assertion(ctx.credential, listed.bytes)

      assert {:error, :unknown_credential} =
               verify_authentication(ctx.strategy, ctx.credential, response, listed, ctx.allowed)
    end

    test "rejects another challenge, origin, relying party or ceremony type", ctx do
      response = Mock.assertion(ctx.credential, :crypto.strong_rand_bytes(32))

      assert {:error, :challenge_mismatch} =
               verify_authentication(
                 ctx.strategy,
                 ctx.credential,
                 response,
                 ctx.challenge,
                 ctx.allowed
               )

      response = Mock.assertion(ctx.credential, ctx.challenge.bytes, origin: "https://evil.com")

      assert {:error, :origin_mismatch} =
               verify_authentication(
                 ctx.strategy,
                 ctx.credential,
                 response,
                 ctx.challenge,
                 ctx.allowed
               )

      response = Mock.assertion(ctx.credential, ctx.challenge.bytes, rp_id: "evil.com")

      assert {:error, :rp_id_mismatch} =
               verify_authentication(
                 ctx.strategy,
                 ctx.credential,
                 response,
                 ctx.challenge,
                 ctx.allowed
               )

      response = Mock.assertion(ctx.credential, ctx.challenge.bytes, type: "webauthn.create")

      assert {:error, :wrong_ceremony_type} =
               verify_authentication(
                 ctx.strategy,
                 ctx.credential,
                 response,
                 ctx.challenge,
                 ctx.allowed
               )
    end

    test "requires user verification only when the strategy does", ctx do
      response = Mock.assertion(ctx.credential, ctx.challenge.bytes, uv: false)

      assert {:ok, _} =
               verify_authentication(
                 ctx.strategy,
                 ctx.credential,
                 response,
                 ctx.challenge,
                 ctx.allowed
               )

      required = %{ctx.challenge | user_verification: "required"}

      assert {:error, :user_not_verified} =
               verify_authentication(
                 ctx.strategy,
                 ctx.credential,
                 response,
                 required,
                 ctx.allowed
               )
    end

    test "rejects an expired challenge", ctx do
      response = Mock.assertion(ctx.credential, ctx.challenge.bytes)
      stale = %{ctx.challenge | issued_at: ctx.challenge.issued_at - ctx.challenge.timeout}

      assert {:error, :challenge_expired} =
               verify_authentication(ctx.strategy, ctx.credential, response, stale, ctx.allowed)
    end

    test "rejects an attestation challenge", ctx do
      response = Mock.assertion(ctx.credential, ctx.challenge.bytes)
      reg_challenge = Mock.registration_challenge(ctx.strategy, nil, [])

      assert {:error, :not_an_authentication_challenge} =
               verify_authentication(
                 ctx.strategy,
                 ctx.credential,
                 response,
                 reg_challenge,
                 ctx.allowed
               )
    end
  end
end
