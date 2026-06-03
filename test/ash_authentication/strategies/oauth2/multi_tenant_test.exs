# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.MultiTenantTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.{Info, Strategy.OAuth2.Actions}
  alias AshAuthentication.UserIdentity.Actions, as: IdentityActions
  alias ExampleMultiTenant.{Organisation, User, UserIdentity}
  require Ash.Query

  setup do
    org_a = Ash.create!(Organisation, %{name: "Org A"}, action: :create)
    org_b = Ash.create!(Organisation, %{name: "Org B"}, action: :create)
    {:ok, strategy} = Info.strategy(User, :oauth2)

    %{org_a: org_a, org_b: org_b, strategy: strategy}
  end

  defp oauth_params(nickname, sub) do
    %{
      "user_info" => %{"nickname" => nickname, "uid" => sub, "sub" => sub},
      "oauth_tokens" => %{
        "access_token" => Ecto.UUID.generate(),
        "expires_in" => 86_400,
        "refresh_token" => Ecto.UUID.generate()
      }
    }
  end

  defp build_user(org, username) do
    User
    |> Ash.Changeset.for_create(:register_with_password, %{
      username: username,
      password: "password123",
      password_confirmation: "password123",
      organisation_id: org.id
    })
    |> Ash.Changeset.set_tenant(org)
    |> Ash.create!()
  end

  defp identities_for(org, user) do
    UserIdentity
    |> Ash.Query.filter(user_id == ^user.id)
    |> Ash.Query.set_tenant(org)
    |> Ash.read!(authorize?: false)
  end

  test "the same provider identity registers a distinct user in each tenant", ctx do
    sub = "shared:#{Ecto.UUID.generate()}"

    assert {:ok, user_a} =
             Actions.register(ctx.strategy, oauth_params("alice_a", sub), tenant: ctx.org_a)

    assert {:ok, user_b} =
             Actions.register(ctx.strategy, oauth_params("alice_b", sub), tenant: ctx.org_b)

    refute user_a.id == user_b.id
    assert user_a.organisation_id == ctx.org_a.id
    assert user_b.organisation_id == ctx.org_b.id

    # The provider's `sub` resolves independently per tenant: each registration
    # creates its own user rather than the second being coerced onto the first.
    assert to_string(user_a.username) == "alice_a"
    assert to_string(user_b.username) == "alice_b"

    assert [identity_a] = identities_for(ctx.org_a, user_a)
    assert [identity_b] = identities_for(ctx.org_b, user_b)
    assert identity_a.organisation_id == ctx.org_a.id
    assert identity_b.organisation_id == ctx.org_b.id
  end

  test "a returning sign-in resolves to the user within the calling tenant", ctx do
    strategy = %{ctx.strategy | registration_enabled?: false}
    sub = "shared:#{Ecto.UUID.generate()}"

    user_a = build_user(ctx.org_a, "alice_a")
    user_b = build_user(ctx.org_b, "alice_b")

    seed_identity = fn org, user ->
      {:ok, _} =
        IdentityActions.upsert(
          UserIdentity,
          %{user_info: %{"sub" => sub}, oauth_tokens: %{}, strategy: :oauth2, user_id: user.id},
          tenant: org
        )
    end

    seed_identity.(ctx.org_a, user_a)
    seed_identity.(ctx.org_b, user_b)

    assert {:ok, signed_in_a} =
             Actions.sign_in(strategy, oauth_params("alice_a", sub), tenant: ctx.org_a)

    assert {:ok, signed_in_b} =
             Actions.sign_in(strategy, oauth_params("alice_b", sub), tenant: ctx.org_b)

    assert signed_in_a.id == user_a.id
    assert signed_in_b.id == user_b.id
  end
end
