# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.ManagementTest do
  use DataCase, async: false

  alias AshAuthentication.{Errors.AuthenticationFailed, Info, Strategy.WebAuthn.Actions}
  alias AshAuthentication.Test.WebAuthnFixtures

  @moduletag feature: :webauthn

  setup do
    strategy = Info.strategy!(Example.UserWithWebAuthn, :webauthn)

    # Create a user with two credentials directly via Ash
    user =
      Example.UserWithWebAuthn
      |> Ash.Changeset.for_create(:create, %{
        email: "manage-test-#{System.unique_integer()}@example.com"
      })
      |> Ash.create!()

    fixture1 = WebAuthnFixtures.generate_registration()
    fixture2 = WebAuthnFixtures.generate_registration()

    cred1 =
      build_webauthn_credential(user, %{
        credential_id: fixture1.credential_id,
        public_key: fixture1.cose_key,
        label: "YubiKey Blue"
      })

    cred2 =
      build_webauthn_credential(user, %{
        credential_id: fixture2.credential_id,
        public_key: fixture2.cose_key,
        label: "MacBook Touch ID"
      })

    %{strategy: strategy, user: user, cred1: cred1, cred2: cred2}
  end

  describe "list_credentials/3" do
    test "returns all credentials for a user", %{strategy: strategy, user: user} do
      {:ok, credentials} = Actions.list_credentials(strategy, user, [])
      assert length(credentials) == 2
    end
  end

  describe "delete_credential/4" do
    test "deletes a credential when more than one exists", %{
      strategy: strategy,
      user: user,
      cred1: cred1
    } do
      assert :ok = Actions.delete_credential(strategy, user, cred1.id, [])
      {:ok, remaining} = Actions.list_credentials(strategy, user, [])
      assert length(remaining) == 1
    end

    test "refuses to delete the last credential", %{
      strategy: strategy,
      user: user,
      cred1: cred1,
      cred2: cred2
    } do
      :ok = Actions.delete_credential(strategy, user, cred1.id, [])
      assert {:error, _} = Actions.delete_credential(strategy, user, cred2.id, [])
    end

    test "treats another user's credential as not found and leaves it", %{
      strategy: strategy,
      user: user,
      cred1: cred1
    } do
      other = other_user_with_credentials(2)

      assert {:error, %AuthenticationFailed{caused_by: %{message: "Credential not found"}}} =
               Actions.delete_credential(strategy, other, cred1.id, [])

      {:ok, credentials} = Actions.list_credentials(strategy, user, [])
      assert length(credentials) == 2
    end
  end

  describe "update_credential_label/5" do
    test "renames a credential", %{strategy: strategy, user: user, cred1: cred1} do
      assert {:ok, updated} =
               Actions.update_credential_label(strategy, user, cred1.id, "New Name", [])

      assert updated.label == "New Name"
    end

    test "treats another user's credential as not found and leaves it", %{
      strategy: strategy,
      user: user,
      cred1: cred1
    } do
      other = other_user_with_credentials(1)

      assert {:error, %AuthenticationFailed{caused_by: %{message: "Credential not found"}}} =
               Actions.update_credential_label(strategy, other, cred1.id, "Hijacked", [])

      {:ok, credentials} = Actions.list_credentials(strategy, user, [])
      assert Enum.find(credentials, &(&1.id == cred1.id)).label == "YubiKey Blue"
    end
  end

  defp other_user_with_credentials(count) do
    other =
      Example.UserWithWebAuthn
      |> Ash.Changeset.for_create(:create, %{
        email: "manage-other-#{System.unique_integer()}@example.com"
      })
      |> Ash.create!()

    for _ <- 1..count do
      fixture = WebAuthnFixtures.generate_registration()

      build_webauthn_credential(other, %{
        credential_id: fixture.credential_id,
        public_key: fixture.cose_key
      })
    end

    other
  end
end
