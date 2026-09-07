# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthenticationTest do
  @moduledoc false
  use DataCase, async: true
  import AshAuthentication
  doctest AshAuthentication

  describe "do_subject_to_user/3" do
    test "it rejects a subject minted for a different resource" do
      {user, other_user} = build_colliding_users()

      assert {:error, _} =
               do_subject_to_user(
                 URI.parse("user_with_remember_me?id=#{other_user.id}"),
                 Example.User,
                 []
               )

      assert user.id == other_user.id
    end

    test "it rejects a subject which names a non-primary-key field" do
      user = build_user()

      assert {:error, _} =
               do_subject_to_user(URI.parse("user?username=#{user.username}"), Example.User, [])
    end

    test "it rejects a subject with an empty query, even when only one user exists" do
      build_user()

      assert {:error, _} = do_subject_to_user(URI.parse("user?"), Example.User, [])
    end
  end

  describe "authenticated_resources/0" do
    test "it correctly locates all authenticatable resources" do
      assert Enum.sort([
               Example.User,
               Example.UserWithAuditLog,
               Example.UserWithConfirmationFieldPolicy,
               Example.UserWithEmptyIncludes,
               Example.UserWithExcludedActions,
               Example.UserWithExcludedStrategies,
               Example.UserWithExplicitIncludes,
               Example.UserWithExtraClaims,
               Example.UserWithFailingSender,
               Example.UserWithOAuthAuditLog,
               Example.UserWithOtp,
               Example.UserWithRecoveryCodes,
               Example.UserWithRegisterOtp,
               Example.UserWithRequiredConfirmation,
               Example.UserWithRenamedAuditLog,
               Example.UserWithSelectiveStrategyIncludes,
               Example.UserWithTokenRequired,
               Example.UserWithUnselectedConfirmation,
               Example.UserWithTotp,
               Example.UserWithTotpConfirmSetup,
               Example.UserWithUnstoredSignInTokens,
               Example.UserWithUnstoredWebAuthn,
               Example.UserWithRememberMe,
               Example.UserWithRememberMeTokenOptional,
               Example.UserWithRegisterMagicLink,
               Example.UserWithWebAuthn,
               Example.UserWithWildcardAndExclusions,
               Example.MultiTenantUserWithWebAuthn,
               ExampleMultiTenant.User,
               ExampleMultiTenant.GlobalUser,
               ExampleMultiTenant.UserWithTokenRequired,
               ExampleMultiTenant.UserWithRegisterMagicLink
             ]) ==
               Enum.sort(authenticated_resources(:ash_authentication))
    end
  end

  # Both resources declare `uuid_primary_key :id, writable?: true` so that a
  # test can deliberately put the same primary key in both tables. That is test
  # scaffolding for constructing the collision the attack needs. A generated
  # resource has a non-writable primary key and no action which accepts `:id`.
  defp build_colliding_users do
    other_user = build_user_with_remember_me()
    {build_user(id: other_user.id), other_user}
  end
end
