# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.SignCountCustomFieldTest do
  @moduledoc """
  Regression test for the assertion-state update using the *configured*
  credential field names rather than hardcoded `:sign_count` / `:last_used_at`
  / `:backed_up`. With a customised `sign_count_field`, a hardcoded update
  would target a non-existent attribute and the sign count would silently
  never advance (defeating clone detection).
  """
  use ExUnit.Case, async: true

  alias Ash.Resource.Info, as: ResourceInfo
  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Strategy.WebAuthn.Actions
  alias AshAuthentication.Test.WebAuthnFixtures

  @moduletag feature: :webauthn

  setup_all do
    suffix = System.unique_integer([:positive])
    user_name = "AshAuthentication.Strategy.WebAuthn.SignCountCustomFieldTest.User#{suffix}"

    credential_name =
      "AshAuthentication.Strategy.WebAuthn.SignCountCustomFieldTest.Credential#{suffix}"

    source = """
    defmodule #{user_name} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication]

      attributes do
        uuid_primary_key :id
      end

      ets do
        private?(true)
      end

      actions do
        defaults [:read, :create, :update, :destroy]
      end

      authentication do
        session_identifier(:jti)

        tokens do
          enabled? true
          token_resource Example.Token
          signing_secret &Example.User.get_config/2
        end

        strategies do
          webauthn :webauthn do
            credential_resource #{credential_name}
            rp_id "example.com"
            rp_name "Test App"
            origin "https://example.com"
            require_identity? false
          end
        end
      end
    end

    defmodule #{credential_name} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication.WebAuthnCredential]

      ets do
        private?(true)
      end

      webauthn_credential do
        user_resource #{user_name}
        user_relationship_name :user#{suffix}
        sign_count_field :counter
      end
    end
    """

    Code.compile_string(source)

    user_module = Module.concat([user_name])
    credential_module = Module.concat([credential_name])

    %{
      strategy: Info.strategy!(user_module, :webauthn),
      credential_module: credential_module
    }
  end

  test "the assertion updates the configured sign-count field, not a hardcoded :sign_count", %{
    strategy: strategy,
    credential_module: credential_module
  } do
    # Sanity: the field really is renamed, so a hardcoded `:sign_count` would miss.
    assert WebAuthn.sign_count_field(strategy) == :counter
    assert ResourceInfo.attribute(credential_module, :counter)
    refute ResourceInfo.attribute(credential_module, :sign_count)

    reg_fixture =
      WebAuthnFixtures.generate_registration(origin: "https://example.com", rp_id: "example.com")

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
          "attestation_object" => reg_fixture.attestation_object,
          "client_data_json" => reg_fixture.client_data_json,
          "raw_id" => reg_fixture.raw_id
        },
        challenge: reg_challenge
      )

    # Read the credential straight off the resource (avoids `list_credentials`,
    # which is unrelated to what we're asserting here).
    assert [credential] = Ash.read!(credential_module, authorize?: false)
    assert credential.counter == 0

    # A valid assertion moves the (renamed) counter forward to 9.
    auth_fixture = WebAuthnFixtures.generate_authentication(reg_fixture, sign_count: 9)

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

    assert {:ok, _user} = Actions.sign_in(strategy, params, challenge: auth_challenge)

    assert [credential] = Ash.read!(credential_module, authorize?: false)

    assert credential.counter == 9,
           "expected the configured `:counter` field to advance to 9; a hardcoded " <>
             "`:sign_count` update would have left it unchanged"
  end
end
