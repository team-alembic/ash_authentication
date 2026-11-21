# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.CustomCredentialNamesTest do
  @moduledoc """
  Credential management against a credential resource that renames what the
  `webauthn_credential` section lets it rename: the label attribute, the
  destroy action, and (outside the section) its primary key.

  Each of these used to be hardcoded somewhere in `Actions` — `%{label: ...}`,
  the primary destroy action, `credential.id` — so a resource customising
  them compiled cleanly and then failed, or did the wrong thing, at runtime.
  """
  use ExUnit.Case, async: true

  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Strategy.WebAuthn.Actions
  alias AshAuthentication.Test.WebAuthnFixtures

  @moduletag feature: :webauthn

  @origin "https://example.com"
  @rp_id "example.com"

  setup_all do
    suffix = System.unique_integer([:positive])
    user_name = "AshAuthentication.Strategy.WebAuthn.CustomCredentialNamesTest.User#{suffix}"

    credential_name =
      "AshAuthentication.Strategy.WebAuthn.CustomCredentialNamesTest.Credential#{suffix}"

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
        defaults [:read, :create]
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
            rp_id "#{@rp_id}"
            rp_name "Test App"
            origin "#{@origin}"
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
        label_field :nickname
        destroy_action_name :revoke
      end

      attributes do
        uuid_primary_key :credential_key
        attribute :revoked_at, :utc_datetime_usec, public?: true
      end

      actions do
        # The register action manages credentials with `:direct_control`,
        # which needs a primary destroy action on this resource. That is
        # the action the old code ran instead of `destroy_action_name`.
        defaults [:destroy]

        # A soft destroy, so the test can see that this action — and not
        # the primary destroy — is the one that ran.
        destroy :revoke do
          soft? true
          require_atomic? false
          change set_attribute(:revoked_at, &DateTime.utc_now/0)
        end
      end
    end
    """

    Code.compile_string(source)

    %{strategy: Info.strategy!(Module.concat([user_name]), :webauthn)}
  end

  setup %{strategy: strategy} do
    first = WebAuthnFixtures.generate_registration(origin: @origin, rp_id: @rp_id)
    second = WebAuthnFixtures.generate_registration(origin: @origin, rp_id: @rp_id)

    {:ok, user} =
      Actions.register(strategy, registration_params(first, "First key"),
        challenge: attestation_challenge(first)
      )

    {:ok, _} =
      Actions.add_credential(strategy, registration_params(second, "Second key"),
        challenge: attestation_challenge(second),
        user: user
      )

    {:ok, credentials} = Actions.list_credentials(strategy, user, [])

    %{user: user, credentials: credentials}
  end

  test "the stored label lands in the configured label field", %{
    strategy: strategy,
    credentials: credentials
  } do
    assert WebAuthn.label_field(strategy) == :nickname
    assert credentials |> Enum.map(& &1.nickname) |> Enum.sort() == ["First key", "Second key"]
  end

  test "update_credential_label/4 writes the configured label field", %{
    strategy: strategy,
    credentials: [credential | _]
  } do
    assert {:ok, updated} =
             Actions.update_credential_label(strategy, credential.credential_key, "Renamed", [])

    assert updated.nickname == "Renamed"
  end

  test "delete_credential/4 finds the credential by its primary key and runs the configured destroy action",
       %{strategy: strategy, user: user, credentials: [credential | _]} do
    assert :ok = Actions.delete_credential(strategy, user, credential.credential_key, [])

    # `:revoke` is a soft destroy, so the record is still there, stamped.
    {:ok, credentials} = Actions.list_credentials(strategy, user, [])
    revoked = Enum.find(credentials, &(&1.credential_key == credential.credential_key))

    assert %DateTime{} = revoked.revoked_at
  end

  test "delete_credential/4 reports an unknown primary key as not found", %{
    strategy: strategy,
    user: user
  } do
    assert {:error, %AshAuthentication.Errors.AuthenticationFailed{}} =
             Actions.delete_credential(strategy, user, Ash.UUID.generate(), [])
  end

  defp registration_params(fixture, label) do
    %{
      "attestation_object" => fixture.attestation_object,
      "client_data_json" => fixture.client_data_json,
      "raw_id" => fixture.raw_id,
      "label" => label
    }
  end

  defp attestation_challenge(fixture) do
    %Wax.Challenge{
      type: :attestation,
      bytes: fixture.challenge_bytes,
      origin: @origin,
      rp_id: @rp_id,
      attestation: "none",
      trusted_attestation_types: [:none, :basic, :self, :uncertain],
      verify_trust_root: false,
      origin_verify_fun: {Wax, :origins_match?, []},
      issued_at: System.system_time(:second)
    }
  end
end
