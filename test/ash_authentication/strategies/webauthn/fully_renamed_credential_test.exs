# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.FullyRenamedCredentialTest do
  @moduledoc """
  Every ceremony against a credential resource that renames every field and
  action its `webauthn_credential` section lets it rename.

  Any code path still reaching for a default name (`:credential_id`,
  `:sign_count`, `:transports`, the `:create`/`:read`/`:update` actions, …)
  fails here, either loudly (unknown attribute or action) or by leaving the
  renamed field unwritten, which the assertions check.
  """
  use DataCase, async: false

  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Strategy.WebAuthn.Actions
  alias AshAuthentication.Test.{WebAuthnCeremony, WebAuthnFixtures}

  @moduletag feature: :webauthn

  @renamed [
    credential_id_field: :key_id,
    public_key_field: :cose_public_key,
    sign_count_field: :counter,
    user_handle_field: :account_handle,
    transports_field: :transport_hints,
    backup_eligible_field: :can_sync,
    backed_up_field: :is_synced,
    discoverable_field: :resident,
    label_field: :nickname,
    last_used_at_field: :seen_at,
    create_action_name: :enrol,
    read_action_name: :all,
    update_action_name: :touch,
    destroy_action_name: :forget
  ]

  setup_all do
    suffix = System.unique_integer([:positive])
    base = "AshAuthentication.Strategy.WebAuthn.FullyRenamedCredentialTest"
    user = "#{base}.User#{suffix}"
    credential = "#{base}.Credential#{suffix}"

    options =
      Enum.map_join(@renamed, "\n    ", fn {option, name} -> "#{option} #{inspect(name)}" end)

    # The user resource is compiled first: the credential extension reads its
    # primary key.
    Code.compile_string("""
    defmodule #{user} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication]

      ets do
        private?(true)
      end

      attributes do
        uuid_primary_key :id
      end

      actions do
        defaults [:read]
      end

      relationships do
        has_many :webauthn_credentials, #{credential},
          destination_attribute: :user#{suffix}_id
      end

      authentication do
        session_identifier(:jti)

        tokens do
          enabled? true
          store_all_tokens? true
          token_resource Example.Token
          signing_secret &Example.User.get_config/2
        end

        strategies do
          webauthn :webauthn do
            credential_resource #{credential}
            require_identity? false
            rp_id "example.com"
            rp_name "Test App"
            origin "https://example.com"
          end
        end
      end
    end

    defmodule #{credential} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication.WebAuthnCredential]

      ets do
        private?(true)
      end

      webauthn_credential do
        user_resource #{user}
        user_relationship_name :user#{suffix}
        #{options}
      end
    end
    """)

    %{
      strategy: Info.strategy!(Module.concat([user]), :webauthn),
      credential: Module.concat([credential])
    }
  end

  test "the resource has the renamed attributes and actions, and none of the defaults", ctx do
    for {option, name} <- @renamed do
      if option |> to_string() |> String.ends_with?("_action_name") do
        assert Ash.Resource.Info.action(ctx.credential, name), "missing action #{name}"
      else
        assert Ash.Resource.Info.attribute(ctx.credential, name), "missing attribute #{name}"
      end
    end

    for default <- [:credential_id, :public_key, :sign_count, :transports, :label] do
      refute Ash.Resource.Info.attribute(ctx.credential, default)
    end

    for default <- [:create, :read, :update, :destroy] do
      refute Ash.Resource.Info.action(ctx.credential, default)
    end

    assert WebAuthn.credential_id_field(ctx.strategy) == :key_id
    assert WebAuthn.sign_count_field(ctx.strategy) == :counter
  end

  test "registration stores every field under its configured name", ctx do
    {:ok, challenge} = Actions.registration_challenge(ctx.strategy, nil)

    passkey =
      WebAuthnFixtures.generate_registration(
        origin: "https://example.com",
        rp_id: "example.com",
        challenge_bytes: ctx.strategy.adapter.challenge_bytes(challenge),
        # UP | BE | BS | AT: a synced passkey
        flags: 0x59
      )

    {:ok, user} =
      Actions.register(
        ctx.strategy,
        %{
          "attestation_object" => passkey.attestation_object,
          "client_data_json" => passkey.client_data_json,
          "raw_id" => passkey.raw_id,
          "label" => "Phone",
          "transports" => ["hybrid", "internal"],
          "cred_props" => %{"rk" => true}
        },
        challenge: challenge,
        user_handle: "handle-bytes"
      )

    assert {:ok, [credential]} = Actions.list_credentials(ctx.strategy, user, [])

    assert credential.key_id == passkey.credential_id
    assert credential.cose_public_key == passkey.cose_key
    assert credential.counter == 0
    assert credential.account_handle == "handle-bytes"
    assert credential.transport_hints == ["hybrid", "internal"]
    assert credential.can_sync == true
    assert credential.is_synced == true
    assert credential.resident == true
    assert credential.nickname == "Phone"
  end

  test "sign-in reads and refreshes the renamed fields", ctx do
    {{:ok, user}, passkey} = WebAuthnCeremony.register(ctx.strategy)

    assert {:ok, _} = WebAuthnCeremony.sign_in(ctx.strategy, passkey, %{}, sign_count: 7)

    assert {:ok, [credential]} = Actions.list_credentials(ctx.strategy, user, [])
    assert credential.counter == 7
    assert %DateTime{} = credential.seen_at

    # The renamed counter is what clone detection compares against.
    assert {:error, _} = WebAuthnCeremony.sign_in(ctx.strategy, passkey, %{}, sign_count: 7)
  end

  test "verify, add, relabel and delete go through the renamed actions", ctx do
    {{:ok, user}, passkey} = WebAuthnCeremony.register(ctx.strategy)

    assert {:ok, _} = WebAuthnCeremony.verify(ctx.strategy, user, passkey)
    assert {{:ok, _}, _second} = WebAuthnCeremony.add_credential(ctx.strategy, user)

    {:ok, [first, second]} = Actions.list_credentials(ctx.strategy, user, [])

    assert {:ok, renamed} = Actions.update_credential_label(ctx.strategy, first.id, "Laptop", [])
    assert renamed.nickname == "Laptop"

    assert :ok = Actions.delete_credential(ctx.strategy, user, second.id, [])
    assert {:ok, [remaining]} = Actions.list_credentials(ctx.strategy, user, [])
    assert remaining.id == first.id
  end
end
