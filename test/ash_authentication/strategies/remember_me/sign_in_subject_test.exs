# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.RememberMe.SignInSubjectTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.Jwt
  alias Example.UserWithRememberMe

  describe "subject validation" do
    test "it rejects a remember me token minted for a different resource" do
      {user, other_user} = build_colliding_users()

      {:ok, token, _claims} =
        Jwt.token_for_user(other_user, %{"purpose" => "remember_me"}, purpose: :remember_me)

      assert {:error, _} = sign_in_with_remember_me(token)
      assert user.id == other_user.id
    end

    test "it rejects a subject which names a non-primary-key field" do
      user = build_user_with_remember_me()

      token =
        sign_token_with_subject(
          UserWithRememberMe,
          "user_with_remember_me?username=#{user.username}",
          remember_me()
        )

      assert {:error, _} = sign_in_with_remember_me(token)
    end

    test "it rejects a subject with an empty query, even when only one user exists" do
      build_user_with_remember_me()

      token =
        sign_token_with_subject(UserWithRememberMe, "user_with_remember_me?", remember_me())

      assert {:error, _} = sign_in_with_remember_me(token)
    end
  end

  defp remember_me, do: %{"purpose" => "remember_me"}

  defp sign_in_with_remember_me(token) do
    UserWithRememberMe
    |> Ash.Query.new()
    |> Ash.Query.for_read(:sign_in_with_remember_me, %{token: token})
    |> Ash.read()
  end

  # Both resources declare `uuid_primary_key :id, writable?: true` so that a
  # test can deliberately put the same primary key in both tables. That is test
  # scaffolding for constructing the collision the attack needs. A generated
  # resource has a non-writable primary key and no action which accepts `:id`.
  defp build_colliding_users do
    user = build_user_with_remember_me()
    {user, build_user(id: user.id)}
  end
end
