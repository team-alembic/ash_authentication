# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.ApiKeyMultiTenantTest do
  @moduledoc false
  use DataCase, async: true

  alias ExampleMultiTenant.{ApiKey, Organisation, User}
  require Ash.Query
  import Ash.Expr

  setup do
    org_a =
      Organisation
      |> Ash.Changeset.for_create(:create, %{name: "Org A"})
      |> Ash.create!()

    user_a =
      User
      |> Ash.Changeset.for_create(:register_with_password, %{
        username: "user_a",
        password: "password123",
        password_confirmation: "password123",
        organisation_id: org_a.id
      })
      |> Ash.Changeset.set_tenant(org_a)
      |> Ash.create!()

    org_b =
      Organisation
      |> Ash.Changeset.for_create(:create, %{name: "Org B"})
      |> Ash.create!()

    user_b =
      User
      |> Ash.Changeset.for_create(:register_with_password, %{
        username: "user_b",
        password: "password123",
        password_confirmation: "password123",
        organisation_id: org_b.id
      })
      |> Ash.Changeset.set_tenant(org_b)
      |> Ash.create!()

    %{
      org_a: org_a,
      org_b: org_b,
      user_a: user_a,
      user_b: user_b
    }
  end

  describe "global API key tests (multitenancy_relationship: nil)" do
    test "global api key authenticates user globally", %{user_a: user_a, org_a: org_a} do
      api_key =
        ApiKey
        |> Ash.Changeset.for_create(:create, %{
          user_id: user_a.id,
          organisation_id: org_a.id,
          expires_at: DateTime.utc_now() |> DateTime.add(1, :day)
        })
        |> Ash.Changeset.set_tenant(org_a)
        |> Ash.create!(authorize?: false)

      plaintext_api_key = api_key.__metadata__.plaintext_api_key

      # Authenticate without tenant context
      result =
        User
        |> Ash.Query.for_read(:sign_in_with_api_key_global, %{api_key: plaintext_api_key})
        |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
        |> Ash.read_one()

      assert {:ok, auth_user} = result
      assert auth_user.id == user_a.id
      assert auth_user.username == user_a.username

      assert auth_user.__metadata__.tenant == nil
      assert auth_user.__metadata__.using_api_key?
    end
  end

  describe "tenant-bound API key tests (multitenancy_relationship: :organisation)" do
    test "tenant api key authenticates user in correct tenant", %{user_a: user_a, org_a: org_a} do
      api_key =
        ApiKey
        |> Ash.Changeset.for_create(:create, %{
          user_id: user_a.id,
          organisation_id: org_a.id,
          expires_at: DateTime.utc_now() |> DateTime.add(1, :day)
        })
        |> Ash.Changeset.set_tenant(org_a)
        |> Ash.create!(authorize?: false)

      plaintext_api_key = api_key.__metadata__.plaintext_api_key

      # Authenticate with org A context
      result =
        User
        |> Ash.Query.for_read(:sign_in_with_api_key_tenant, %{api_key: plaintext_api_key})
        |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
        |> Ash.Query.set_tenant(org_a)
        |> Ash.read_one()

      assert {:ok, auth_user} = result
      assert auth_user.id == user_a.id
      assert auth_user.username == user_a.username

      assert %Organisation{} = auth_user.__metadata__.tenant
      assert auth_user.__metadata__.tenant.id == org_a.id
      assert auth_user.__metadata__.using_api_key?
    end

    test "tenant api key fails authentication in wrong tenant", %{
      user_a: user_a,
      org_a: org_a,
      org_b: org_b
    } do
      # Create tenant API key in org A
      api_key =
        ApiKey
        |> Ash.Changeset.for_create(:create, %{
          user_id: user_a.id,
          organisation_id: org_a.id,
          expires_at: DateTime.utc_now() |> DateTime.add(1, :day)
        })
        |> Ash.Changeset.set_tenant(org_a)
        |> Ash.create!(authorize?: false)

      plaintext_api_key = api_key.__metadata__.plaintext_api_key

      # Try to authenticate with org B context - should fail
      result =
        User
        |> Ash.Query.for_read(:sign_in_with_api_key_tenant, %{api_key: plaintext_api_key})
        |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
        |> Ash.Query.set_tenant(org_b)
        |> Ash.read_one()

      assert {:error, %Ash.Error.Forbidden{}} = result
    end

    test "tenant api key authenticates globally with tenant context", %{
      user_a: user_a,
      org_a: org_a
    } do
      api_key =
        ApiKey
        |> Ash.Changeset.for_create(:create, %{
          user_id: user_a.id,
          organisation_id: org_a.id,
          expires_at: DateTime.utc_now() |> DateTime.add(1, :day)
        })
        |> Ash.Changeset.set_tenant(org_a)
        |> Ash.create!(authorize?: false)

      plaintext_api_key = api_key.__metadata__.plaintext_api_key

      # Authenticate without tenant context
      result =
        User
        |> Ash.Query.for_read(:sign_in_with_api_key_tenant, %{api_key: plaintext_api_key})
        |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
        |> Ash.read_one()

      assert {:ok, auth_user} = result
      assert auth_user.id == user_a.id

      assert %Organisation{} = auth_user.__metadata__.tenant
      assert auth_user.__metadata__.tenant.id == org_a.id
      assert auth_user.__metadata__.using_api_key?
    end
  end

  describe "API key-tenant relationship tests" do
    test "tenant api key has correct organisation relationship", %{user_a: user_a, org_a: org_a} do
      api_key =
        ApiKey
        |> Ash.Changeset.for_create(:create, %{
          user_id: user_a.id,
          organisation_id: org_a.id,
          expires_at: DateTime.utc_now() |> DateTime.add(1, :day)
        })
        |> Ash.Changeset.set_tenant(org_a)
        |> Ash.create!(authorize?: false)

      api_key_with_org =
        ApiKey
        |> Ash.Query.filter(expr(id == ^api_key.id))
        |> Ash.Query.load(:organisation)
        |> Ash.Query.set_tenant(org_a)
        |> Ash.read_one!(authorize?: false)

      assert %Organisation{} = api_key_with_org.organisation
      assert api_key_with_org.organisation.id == org_a.id
      assert api_key_with_org.organisation.name == org_a.name
    end

    test "api key metadata includes tenant information", %{user_a: user_a, org_a: org_a} do
      api_key =
        ApiKey
        |> Ash.Changeset.for_create(:create, %{
          user_id: user_a.id,
          organisation_id: org_a.id,
          expires_at: DateTime.utc_now() |> DateTime.add(1, :day)
        })
        |> Ash.Changeset.set_tenant(org_a)
        |> Ash.create!(authorize?: false)

      plaintext_api_key = api_key.__metadata__.plaintext_api_key

      # Authenticate with tenant API key
      result =
        User
        |> Ash.Query.for_read(:sign_in_with_api_key_tenant, %{api_key: plaintext_api_key})
        |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
        |> Ash.Query.set_tenant(org_a)
        |> Ash.read_one()

      assert {:ok, auth_user} = result

      assert %Organisation{} = auth_user.__metadata__.tenant
      assert auth_user.__metadata__.tenant.id == org_a.id

      assert %ApiKey{} = auth_user.__metadata__.api_key
      assert auth_user.__metadata__.api_key.id == api_key.id
      assert auth_user.__metadata__.api_key.organisation.id == org_a.id
      assert auth_user.__metadata__.using_api_key?
    end
  end
end
