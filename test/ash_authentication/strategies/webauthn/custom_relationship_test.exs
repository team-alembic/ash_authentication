# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.CustomRelationshipTest do
  @moduledoc """
  Regression test for credential management resolving the user via the
  *configured* `belongs_to` foreign key rather than a hardcoded `:user_id` /
  `user.id`. With a customised `user_relationship_name` the foreign key is not
  `user_id`, so `list_credentials/3` used to fail with "Invalid reference
  user_id" and `add_credential/3` would write to a non-existent column.
  """
  use ExUnit.Case, async: true

  alias Ash.Resource.Info, as: ResourceInfo
  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.WebAuthn.Actions
  alias AshAuthentication.Test.WebAuthnFixtures

  @moduletag feature: :webauthn

  setup_all do
    suffix = System.unique_integer([:positive])
    user_name = "AshAuthentication.Strategy.WebAuthn.CustomRelationshipTest.User#{suffix}"

    credential_name =
      "AshAuthentication.Strategy.WebAuthn.CustomRelationshipTest.Credential#{suffix}"

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
        # A non-default relationship name → foreign key `user#{suffix}_id`,
        # NOT `user_id`.
        user_relationship_name :user#{suffix}
      end

      identities do
        identity :unique_credential_id, [:credential_id],
          pre_check_with: AshAuthentication.Test.PermissiveDomain
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

  test "the configured foreign key really isn't `user_id`", %{credential_module: credential_module} do
    refute ResourceInfo.attribute(credential_module, :user_id)

    assert Enum.any?(
             ResourceInfo.attributes(credential_module),
             &(&1.name |> to_string() |> String.ends_with?("_id"))
           )
  end

  test "list_credentials resolves via the configured foreign key", %{strategy: strategy} do
    {user, _fixture} = register(strategy, "list")

    # Before the fix this raised `Invalid reference user_id`.
    assert {:ok, [credential]} = Actions.list_credentials(strategy, user, [])
    assert credential
  end

  test "add_credential writes the configured foreign key", %{strategy: strategy} do
    {user, _fixture} = register(strategy, "add")

    add_fixture =
      WebAuthnFixtures.generate_registration(origin: "https://example.com", rp_id: "example.com")

    assert {:ok, _credential} =
             Actions.add_credential(
               strategy,
               %{
                 "attestation_object" => add_fixture.attestation_object,
                 "client_data_json" => add_fixture.client_data_json,
                 "raw_id" => add_fixture.raw_id
               },
               user: user,
               challenge: attestation_challenge(add_fixture)
             )

    # Both credentials now hang off the user via the custom foreign key.
    assert {:ok, credentials} = Actions.list_credentials(strategy, user, [])
    assert length(credentials) == 2
  end

  defp register(strategy, tag) do
    fixture =
      WebAuthnFixtures.generate_registration(origin: "https://example.com", rp_id: "example.com")

    {:ok, user} =
      Actions.register(
        strategy,
        %{
          "attestation_object" => fixture.attestation_object,
          "client_data_json" => fixture.client_data_json,
          "raw_id" => fixture.raw_id,
          "label" => "key-#{tag}"
        },
        challenge: attestation_challenge(fixture)
      )

    {user, fixture}
  end

  defp attestation_challenge(fixture) do
    %Wax.Challenge{
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
  end
end
