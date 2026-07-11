# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.ActionsTest do
  use DataCase, async: false

  require Ash.Query

  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.WebAuthn.Actions
  alias AshAuthentication.Test.WebAuthnFixtures

  @moduletag feature: :webauthn

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

    test "stores the user handle on the credential when supplied", %{strategy: strategy} do
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
        "email" => "handle-user@example.com",
        "attestation_object" => fixture.attestation_object,
        "client_data_json" => fixture.client_data_json,
        "raw_id" => fixture.raw_id
      }

      user_handle = :crypto.strong_rand_bytes(32)

      assert {:ok, user} =
               Actions.register(strategy, params,
                 challenge: challenge,
                 user_handle: user_handle
               )

      {:ok, [credential]} = Actions.list_credentials(strategy, user, [])
      assert credential.user_handle == user_handle
    end

    test "stores transports and backup flags from the ceremony", %{strategy: strategy} do
      fixture =
        WebAuthnFixtures.generate_registration(
          origin: "https://example.com",
          rp_id: "example.com",
          # UP | BE | BS | AT — a synced passkey
          flags: 0x59
        )

      params = %{
        "email" => "flags-user@example.com",
        "attestation_object" => fixture.attestation_object,
        "client_data_json" => fixture.client_data_json,
        "raw_id" => fixture.raw_id,
        "transports" => ["internal", "hybrid", "carrier-pigeon"]
      }

      assert {:ok, user} =
               Actions.register(strategy, params, challenge: registration_challenge(fixture))

      {:ok, [credential]} = Actions.list_credentials(strategy, user, [])
      # Unknown transports are dropped, known ones stored in order
      assert credential.transports == ["internal", "hybrid"]
      assert credential.backup_eligible == true
      assert credential.backed_up == true
    end

    test "persists register_action_accept fields from params", %{strategy: strategy} do
      fixture =
        WebAuthnFixtures.generate_registration(
          origin: "https://example.com",
          rp_id: "example.com"
        )

      params = %{
        "email" => "named-webauthn-user@example.com",
        "name" => "Named User",
        "attestation_object" => fixture.attestation_object,
        "client_data_json" => fixture.client_data_json,
        "raw_id" => fixture.raw_id
      }

      assert {:ok, user} =
               Actions.register(strategy, params, challenge: registration_challenge(fixture))

      assert user.name == "Named User"
    end

    test "validates register_action_accept fields via the resource's constraints", %{
      strategy: strategy
    } do
      fixture =
        WebAuthnFixtures.generate_registration(
          origin: "https://example.com",
          rp_id: "example.com"
        )

      params = %{
        "email" => "invalid-name-user@example.com",
        # violates the attribute's `min_length: 2` constraint
        "name" => "x",
        "attestation_object" => fixture.attestation_object,
        "client_data_json" => fixture.client_data_json,
        "raw_id" => fixture.raw_id
      }

      assert {:error, error} =
               Actions.register(strategy, params, challenge: registration_challenge(fixture))

      assert Enum.any?(Ash.Error.to_error_class(error).errors, &(Map.get(&1, :field) == :name))

      assert {:ok, []} =
               Example.UserWithWebAuthn
               |> Ash.Query.filter(email == "invalid-name-user@example.com")
               |> Ash.read()
    end

    test "rolls back user creation when credential creation fails", %{strategy: strategy} do
      credential_id = WebAuthnFixtures.generate_credential_id()

      first_fixture =
        WebAuthnFixtures.generate_registration(
          origin: "https://example.com",
          rp_id: "example.com",
          credential_id: credential_id
        )

      first_challenge = registration_challenge(first_fixture)

      assert {:ok, _first_user} =
               Actions.register(
                 strategy,
                 %{
                   "email" => "first-webauthn-user@example.com",
                   "attestation_object" => first_fixture.attestation_object,
                   "client_data_json" => first_fixture.client_data_json,
                   "raw_id" => first_fixture.raw_id
                 },
                 challenge: first_challenge
               )

      # Reusing the same credential_id violates the credential resource's
      # `unique_credential_id` identity, causing the second create inside
      # `manage_relationship` to fail. Because it now runs inside the same
      # transaction as the user create, the user must not be persisted either.
      colliding_fixture =
        WebAuthnFixtures.generate_registration(
          origin: "https://example.com",
          rp_id: "example.com",
          credential_id: credential_id
        )

      colliding_challenge = registration_challenge(colliding_fixture)

      assert {:error, _error} =
               Actions.register(
                 strategy,
                 %{
                   "email" => "second-webauthn-user@example.com",
                   "attestation_object" => colliding_fixture.attestation_object,
                   "client_data_json" => colliding_fixture.client_data_json,
                   "raw_id" => colliding_fixture.raw_id
                 },
                 challenge: colliding_challenge
               )

      assert {:ok, []} =
               Example.UserWithWebAuthn
               |> Ash.Query.filter(email == "second-webauthn-user@example.com")
               |> Ash.read()
    end
  end

  defp register_user(strategy, email) do
    reg_fixture =
      WebAuthnFixtures.generate_registration(
        origin: "https://example.com",
        rp_id: "example.com"
      )

    {:ok, user} =
      Actions.register(
        strategy,
        %{
          "email" => email,
          "attestation_object" => reg_fixture.attestation_object,
          "client_data_json" => reg_fixture.client_data_json,
          "raw_id" => reg_fixture.raw_id
        },
        challenge: registration_challenge(reg_fixture)
      )

    {user, reg_fixture}
  end

  defp sign_in_with_count(strategy, reg_fixture, email, sign_count) do
    auth_fixture = WebAuthnFixtures.generate_authentication(reg_fixture, sign_count: sign_count)

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
      "email" => email,
      "raw_id" => Base.url_encode64(auth_fixture.raw_id, padding: false),
      "authenticator_data" => auth_fixture.authenticator_data,
      "signature" => auth_fixture.signature,
      "client_data_json" => auth_fixture.client_data_json
    }

    Actions.sign_in(strategy, params, challenge: auth_challenge)
  end

  defp registration_challenge(fixture) do
    %Wax.Challenge{
      type: :attestation,
      bytes: fixture.challenge_bytes,
      origin: fixture.origin,
      rp_id: fixture.rp_id,
      attestation: "none",
      trusted_attestation_types: [:none, :basic, :self, :uncertain],
      verify_trust_root: false,
      origin_verify_fun: {Wax, :origins_match?, []},
      issued_at: System.system_time(:second)
    }
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

    test "refreshes the backup state flag on assertion", %{strategy: strategy} do
      # Register as backup-eligible but not yet backed up (UP | BE | AT)
      reg_fixture =
        WebAuthnFixtures.generate_registration(
          origin: "https://example.com",
          rp_id: "example.com",
          flags: 0x49
        )

      {:ok, user} =
        Actions.register(
          strategy,
          %{
            "email" => "backup-state@example.com",
            "attestation_object" => reg_fixture.attestation_object,
            "client_data_json" => reg_fixture.client_data_json,
            "raw_id" => reg_fixture.raw_id
          },
          challenge: registration_challenge(reg_fixture)
        )

      {:ok, [credential]} = Actions.list_credentials(strategy, user, [])
      assert credential.backup_eligible == true
      assert credential.backed_up == false

      # The credential has since been synced: assert with UP | UV | BE | BS
      auth_fixture = WebAuthnFixtures.generate_authentication(reg_fixture, flags: 0x1D)

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
        "email" => "backup-state@example.com",
        "raw_id" => Base.url_encode64(auth_fixture.raw_id, padding: false),
        "authenticator_data" => auth_fixture.authenticator_data,
        "signature" => auth_fixture.signature,
        "client_data_json" => auth_fixture.client_data_json
      }

      assert {:ok, _user} = Actions.sign_in(strategy, params, challenge: auth_challenge)

      {:ok, [credential]} = Actions.list_credentials(strategy, user, [])
      assert credential.backed_up == true
    end

    test "rejects an assertion whose sign count did not increase", %{strategy: strategy} do
      {user, reg_fixture} = register_user(strategy, "clone-detect@example.com")

      # A legitimate assertion moves the counter to 5
      assert {:ok, _} =
               sign_in_with_count(strategy, reg_fixture, "clone-detect@example.com", 5)

      {:ok, [credential]} = Actions.list_credentials(strategy, user, [])
      assert credential.sign_count == 5

      # A regressed counter is the clone signal — rejected by default
      assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
               sign_in_with_count(strategy, reg_fixture, "clone-detect@example.com", 3)

      # The stored high-water mark is untouched
      {:ok, [credential]} = Actions.list_credentials(strategy, user, [])
      assert credential.sign_count == 5
    end

    test "accepts constant-zero counters (synced passkeys)", %{strategy: strategy} do
      {_user, reg_fixture} = register_user(strategy, "synced-passkey@example.com")

      assert {:ok, _} =
               sign_in_with_count(strategy, reg_fixture, "synced-passkey@example.com", 0)

      assert {:ok, _} =
               sign_in_with_count(strategy, reg_fixture, "synced-passkey@example.com", 0)
    end

    test "sign_count_policy :log allows the assertion but keeps the stored count", %{
      strategy: strategy
    } do
      strategy = %{strategy | sign_count_policy: :log}
      {user, reg_fixture} = register_user(strategy, "lenient-clone@example.com")

      assert {:ok, _} =
               sign_in_with_count(strategy, reg_fixture, "lenient-clone@example.com", 5)

      assert {:ok, _} =
               sign_in_with_count(strategy, reg_fixture, "lenient-clone@example.com", 3)

      {:ok, [credential]} = Actions.list_credentials(strategy, user, [])
      assert credential.sign_count == 5
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

  describe "add_credential/3" do
    test "attaches a credential to an existing user without creating a new user", %{
      strategy: strategy
    } do
      user =
        Ash.create!(Example.UserWithWebAuthn, %{email: "add-cred@example.com"}, action: :create)

      fixture =
        WebAuthnFixtures.generate_registration(
          origin: "https://example.com",
          rp_id: "example.com"
        )

      params = %{
        "attestation_object" => fixture.attestation_object,
        "client_data_json" => fixture.client_data_json,
        "label" => "My Phone"
      }

      assert {:ok, credential} =
               Actions.add_credential(strategy, params,
                 user: user,
                 challenge: registration_challenge(fixture)
               )

      # The credential is attached to the existing user, with the attested data.
      assert credential.user_id == user.id
      assert credential.credential_id == fixture.credential_id
      assert credential.label == "My Phone"

      # No new user was created — `add_credential` must not behave like `register`.
      assert {:ok, [only_user]} = Ash.read(Example.UserWithWebAuthn)
      assert only_user.id == user.id
    end

    test "adds an additional credential alongside an existing one", %{strategy: strategy} do
      # Register a user, which gives them their first credential.
      first_fixture =
        WebAuthnFixtures.generate_registration(
          origin: "https://example.com",
          rp_id: "example.com"
        )

      {:ok, user} =
        Actions.register(
          strategy,
          %{
            "email" => "second-key@example.com",
            "attestation_object" => first_fixture.attestation_object,
            "client_data_json" => first_fixture.client_data_json,
            "raw_id" => first_fixture.raw_id
          },
          challenge: registration_challenge(first_fixture)
        )

      # Enrol a second passkey on the same user (a distinct credential).
      second_fixture =
        WebAuthnFixtures.generate_registration(
          origin: "https://example.com",
          rp_id: "example.com"
        )

      assert {:ok, second_credential} =
               Actions.add_credential(
                 strategy,
                 %{
                   "attestation_object" => second_fixture.attestation_object,
                   "client_data_json" => second_fixture.client_data_json,
                   "label" => "Backup Key"
                 },
                 user: user,
                 challenge: registration_challenge(second_fixture)
               )

      assert second_credential.user_id == user.id

      # Both credentials belong to the user and are distinct.
      assert {:ok, credentials} =
               Example.WebAuthnCredential
               |> Ash.Query.filter(user_id == ^user.id)
               |> Ash.read()

      assert length(credentials) == 2

      credential_ids = Enum.map(credentials, & &1.credential_id)
      assert first_fixture.credential_id in credential_ids
      assert second_fixture.credential_id in credential_ids
    end
  end
end
