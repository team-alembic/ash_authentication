# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.ActionsTest do
  use DataCase, async: false

  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.WebAuthn.Actions
  alias AshAuthentication.Test.WebAuthnFixtures

  setup do
    strategy = Info.strategy!(Example.UserWithWebAuthn, :webauthn)
    %{strategy: strategy}
  end

  describe "registration_challenge/2" do
    test "returns a Wax.Challenge with type :attestation", %{strategy: strategy} do
      assert {:ok, %Wax.Challenge{type: :attestation}} =
               Actions.registration_challenge(strategy, nil)
    end
  end

  describe "authentication_challenge/3" do
    test "returns a Wax.Challenge with type :authentication", %{strategy: strategy} do
      assert {:ok, %Wax.Challenge{type: :authentication}} =
               Actions.authentication_challenge(strategy, [], nil)
    end
  end

  describe "register/3" do
    test "creates user and credential on valid attestation", %{strategy: strategy} do
      fixture =
        WebAuthnFixtures.generate_registration(
          origin: "https://example.com",
          rp_id: "example.com"
        )

      challenge = %Wax.Challenge{
        type: :attestation,
        bytes: fixture.challenge_bytes,
        origin: "https://example.com",
        rp_id: "example.com",
        attestation: "none",
        trusted_attestation_types: [:none, :basic, :self, :uncertain],
        verify_trust_root: false,
        origin_verify_fun: {Wax, :origins_match?, []},
        issued_at: System.system_time(:second)
      }

      params = %{
        "email" => "webauthn-user@example.com",
        "attestation_object" => fixture.attestation_object,
        "client_data_json" => fixture.client_data_json,
        "raw_id" => fixture.raw_id
      }

      assert {:ok, user} = Actions.register(strategy, params, challenge: challenge)
      assert to_string(user.email) == "webauthn-user@example.com"
    end
  end

  describe "sign_in/3" do
    test "authenticates user with valid assertion", %{strategy: strategy} do
      # First register a user
      reg_fixture =
        WebAuthnFixtures.generate_registration(
          origin: "https://example.com",
          rp_id: "example.com"
        )

      reg_challenge = %Wax.Challenge{
        type: :attestation,
        bytes: reg_fixture.challenge_bytes,
        origin: "https://example.com",
        rp_id: "example.com",
        attestation: "none",
        trusted_attestation_types: [:none, :basic, :self, :uncertain],
        verify_trust_root: false,
        origin_verify_fun: {Wax, :origins_match?, []},
        issued_at: System.system_time(:second)
      }

      {:ok, _user} =
        Actions.register(
          strategy,
          %{
            "email" => "signin-test@example.com",
            "attestation_object" => reg_fixture.attestation_object,
            "client_data_json" => reg_fixture.client_data_json,
            "raw_id" => reg_fixture.raw_id
          },
          challenge: reg_challenge
        )

      # Now authenticate
      auth_fixture = WebAuthnFixtures.generate_authentication(reg_fixture)

      auth_challenge = %Wax.Challenge{
        type: :authentication,
        bytes: auth_fixture.challenge_bytes,
        origin: "https://example.com",
        rp_id: "example.com",
        allow_credentials: [{reg_fixture.credential_id, reg_fixture.cose_key}],
        origin_verify_fun: {Wax, :origins_match?, []},
        issued_at: System.system_time(:second)
      }

      params = %{
        "email" => "signin-test@example.com",
        "raw_id" => Base.url_encode64(auth_fixture.raw_id, padding: false),
        "authenticator_data" => auth_fixture.authenticator_data,
        "signature" => auth_fixture.signature,
        "client_data_json" => auth_fixture.client_data_json
      }

      assert {:ok, user} = Actions.sign_in(strategy, params, challenge: auth_challenge)
      assert to_string(user.email) == "signin-test@example.com"
      # Token should be generated (tokens are enabled on Example.UserWithWebAuthn)
      assert user.__metadata__[:token]
    end

    test "returns error for unknown identity", %{strategy: strategy} do
      reg_fixture =
        WebAuthnFixtures.generate_registration(
          origin: "https://example.com",
          rp_id: "example.com"
        )

      auth_fixture = WebAuthnFixtures.generate_authentication(reg_fixture)

      auth_challenge = %Wax.Challenge{
        type: :authentication,
        bytes: auth_fixture.challenge_bytes,
        origin: "https://example.com",
        rp_id: "example.com",
        allow_credentials: [{reg_fixture.credential_id, reg_fixture.cose_key}],
        origin_verify_fun: {Wax, :origins_match?, []},
        issued_at: System.system_time(:second)
      }

      params = %{
        "email" => "nonexistent@example.com",
        "raw_id" => Base.url_encode64(auth_fixture.raw_id, padding: false),
        "authenticator_data" => auth_fixture.authenticator_data,
        "signature" => auth_fixture.signature,
        "client_data_json" => auth_fixture.client_data_json
      }

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               Actions.sign_in(strategy, params, challenge: auth_challenge)
    end
  end

  describe "verify/3" do
    setup %{strategy: strategy} do
      reg_fixture =
        WebAuthnFixtures.generate_registration(
          origin: "https://example.com",
          rp_id: "example.com"
        )

      reg_challenge = %Wax.Challenge{
        type: :attestation,
        bytes: reg_fixture.challenge_bytes,
        origin: "https://example.com",
        rp_id: "example.com",
        attestation: "none",
        trusted_attestation_types: [:none, :basic, :self, :uncertain],
        verify_trust_root: false,
        origin_verify_fun: {Wax, :origins_match?, []},
        issued_at: System.system_time(:second)
      }

      {:ok, user} =
        Actions.register(
          strategy,
          %{
            "email" => "verify-test@example.com",
            "attestation_object" => reg_fixture.attestation_object,
            "client_data_json" => reg_fixture.client_data_json,
            "raw_id" => reg_fixture.raw_id
          },
          challenge: reg_challenge
        )

      %{registration: reg_fixture, user: user}
    end

    test "stamps webauthn_verified_at when the assertion is valid", %{
      strategy: strategy,
      registration: reg_fixture,
      user: user
    } do
      auth_fixture = WebAuthnFixtures.generate_authentication(reg_fixture)

      auth_challenge = %Wax.Challenge{
        type: :authentication,
        bytes: auth_fixture.challenge_bytes,
        origin: "https://example.com",
        rp_id: "example.com",
        allow_credentials: [{reg_fixture.credential_id, reg_fixture.cose_key}],
        origin_verify_fun: {Wax, :origins_match?, []},
        issued_at: System.system_time(:second)
      }

      params = %{
        "raw_id" => Base.url_encode64(auth_fixture.raw_id, padding: false),
        "authenticator_data" => auth_fixture.authenticator_data,
        "signature" => auth_fixture.signature,
        "client_data_json" => auth_fixture.client_data_json
      }

      assert {:ok, verified_user} =
               Actions.verify(strategy, params, actor: user, challenge: auth_challenge)

      assert %DateTime{} = verified_user.__metadata__.webauthn_verified_at
      assert verified_user.__metadata__[:token]
    end

    test "rejects assertions for credentials owned by another user", %{
      strategy: strategy,
      registration: reg_fixture
    } do
      # Register a *second* user with their own credential.
      other_reg =
        WebAuthnFixtures.generate_registration(
          origin: "https://example.com",
          rp_id: "example.com"
        )

      other_reg_challenge = %Wax.Challenge{
        type: :attestation,
        bytes: other_reg.challenge_bytes,
        origin: "https://example.com",
        rp_id: "example.com",
        attestation: "none",
        trusted_attestation_types: [:none, :basic, :self, :uncertain],
        verify_trust_root: false,
        origin_verify_fun: {Wax, :origins_match?, []},
        issued_at: System.system_time(:second)
      }

      {:ok, other_user} =
        Actions.register(
          strategy,
          %{
            "email" => "verify-other@example.com",
            "attestation_object" => other_reg.attestation_object,
            "client_data_json" => other_reg.client_data_json,
            "raw_id" => other_reg.raw_id
          },
          challenge: other_reg_challenge
        )

      # The first user tries to verify using a credential that belongs to
      # the second user — should be rejected.
      auth_fixture = WebAuthnFixtures.generate_authentication(reg_fixture)

      auth_challenge = %Wax.Challenge{
        type: :authentication,
        bytes: auth_fixture.challenge_bytes,
        origin: "https://example.com",
        rp_id: "example.com",
        allow_credentials: [{reg_fixture.credential_id, reg_fixture.cose_key}],
        origin_verify_fun: {Wax, :origins_match?, []},
        issued_at: System.system_time(:second)
      }

      params = %{
        "raw_id" => Base.url_encode64(auth_fixture.raw_id, padding: false),
        "authenticator_data" => auth_fixture.authenticator_data,
        "signature" => auth_fixture.signature,
        "client_data_json" => auth_fixture.client_data_json
      }

      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               Actions.verify(strategy, params, actor: other_user, challenge: auth_challenge)
    end

    test "issues a token containing the webauthn_verified_at claim", %{
      strategy: strategy,
      registration: reg_fixture,
      user: user
    } do
      auth_fixture = WebAuthnFixtures.generate_authentication(reg_fixture)

      auth_challenge = %Wax.Challenge{
        type: :authentication,
        bytes: auth_fixture.challenge_bytes,
        origin: "https://example.com",
        rp_id: "example.com",
        allow_credentials: [{reg_fixture.credential_id, reg_fixture.cose_key}],
        origin_verify_fun: {Wax, :origins_match?, []},
        issued_at: System.system_time(:second)
      }

      params = %{
        "raw_id" => Base.url_encode64(auth_fixture.raw_id, padding: false),
        "authenticator_data" => auth_fixture.authenticator_data,
        "signature" => auth_fixture.signature,
        "client_data_json" => auth_fixture.client_data_json
      }

      {:ok, verified_user} =
        Actions.verify(strategy, params, actor: user, challenge: auth_challenge)

      token = verified_user.__metadata__.token
      {:ok, claims} = AshAuthentication.Jwt.peek(token)
      assert is_binary(claims["webauthn_verified_at"])

      {:ok, parsed, _} = DateTime.from_iso8601(claims["webauthn_verified_at"])
      assert DateTime.diff(DateTime.utc_now(), parsed, :second) < 5
    end
  end
end
