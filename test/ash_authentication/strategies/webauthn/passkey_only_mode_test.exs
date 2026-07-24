# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.PasskeyOnlyModeTest do
  use DataCase, async: false

  alias Ash.Resource.Info, as: ResourceInfo
  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.WebAuthn.Actions
  alias AshAuthentication.Test.WebAuthnFixtures

  setup do
    strategy = Info.strategy!(Example.UserWithWebAuthnNoIdentity, :webauthn)
    %{strategy: strategy}
  end

  describe "compile-time artefacts" do
    test "the strategy compiles on a user resource with no identity attribute", %{
      strategy: strategy
    } do
      assert strategy.require_identity? == false
      refute ResourceInfo.attribute(Example.UserWithWebAuthnNoIdentity, :email)
      assert ResourceInfo.identities(Example.UserWithWebAuthnNoIdentity) == []
    end

    test "the register action does not accept an identity attribute" do
      action = ResourceInfo.action(Example.UserWithWebAuthnNoIdentity, :register_with_webauthn)
      assert action.type == :create
      refute :email in action.accept
    end

    test "the sign_in action's identity argument is nil-able" do
      action = ResourceInfo.action(Example.UserWithWebAuthnNoIdentity, :sign_in_with_webauthn)

      assert action.arguments == [],
             "expected sign-in arguments for WebAuthn without identity to be `[]`"
    end
  end

  describe "SignInPreparation in passkey mode" do
    test "fails closed rather than returning every user" do
      # In passkey-first mode the user is resolved from the credential id in
      # `Actions.sign_in/3`, not by this read action. A direct read of the
      # sign-in action must therefore return nothing rather than enumerating
      # every user in the resource.
      Example.UserWithWebAuthnNoIdentity
      |> Ash.Changeset.for_create(:create, %{})
      |> Ash.create!()

      assert {:ok, []} =
               Example.UserWithWebAuthnNoIdentity
               |> Ash.Query.for_read(:sign_in_with_webauthn, %{})
               |> Ash.read(authorize?: false)
    end
  end

  describe "end-to-end passkey flow" do
    test "registers and signs in with no identity in the request", %{strategy: strategy} do
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

      # No identity (email) anywhere in the request body.
      assert {:ok, user} =
               Actions.register(
                 strategy,
                 %{
                   "attestation_object" => reg_fixture.attestation_object,
                   "client_data_json" => reg_fixture.client_data_json,
                   "raw_id" => reg_fixture.raw_id
                 },
                 challenge: reg_challenge
               )

      assert user.__metadata__[:token]

      auth_fixture = WebAuthnFixtures.generate_authentication(reg_fixture)

      # Discoverable-credential flow: no allow_credentials restriction.
      auth_challenge = %Wax.Challenge{
        type: :authentication,
        bytes: auth_fixture.challenge_bytes,
        origin: "https://example.com",
        rp_id: "example.com",
        allow_credentials: [],
        origin_verify_fun: {Wax, :origins_match?, []},
        issued_at: System.system_time(:second)
      }

      params = %{
        "raw_id" => Base.url_encode64(auth_fixture.raw_id, padding: false),
        "authenticator_data" => auth_fixture.authenticator_data,
        "signature" => auth_fixture.signature,
        "client_data_json" => auth_fixture.client_data_json
      }

      assert {:ok, signed_in} = Actions.sign_in(strategy, params, challenge: auth_challenge)
      assert signed_in.id == user.id
      assert signed_in.__metadata__[:token]
    end

    test "sign in fails for an unknown credential", %{strategy: strategy} do
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
        allow_credentials: [],
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
               Actions.sign_in(strategy, params, challenge: auth_challenge)
    end
  end
end
