# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Password.SignInWithTokenPreparationTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.{Errors.AuthenticationFailed, Info, Jwt}
  alias AshAuthentication.Strategy.Password.Actions

  describe "subject validation" do
    test "it rejects a sign-in token minted for a different resource" do
      {user, other_user} = build_colliding_users()

      {:ok, token, _claims} =
        Jwt.token_for_user(other_user, %{"purpose" => "sign_in"}, purpose: :sign_in)

      assert {:error, %AuthenticationFailed{}} = sign_in_with_token(token)
      assert user.id == other_user.id
    end

    test "it rejects a subject which names a non-primary-key field" do
      user = build_user()
      token = sign_token_with_subject(Example.User, "user?username=#{user.username}", sign_in())

      assert {:error, %AuthenticationFailed{}} = sign_in_with_token(token)
    end

    test "it rejects a subject with an empty query, even when only one user exists" do
      build_user()
      token = sign_token_with_subject(Example.User, "user?", sign_in())

      assert {:error, %AuthenticationFailed{}} = sign_in_with_token(token)
    end
  end

  defp sign_in, do: %{"purpose" => "sign_in"}

  defp sign_in_with_token(token) do
    {:ok, strategy} = Info.strategy(Example.User, :password)

    Actions.sign_in_with_token(strategy, %{"token" => token}, [])
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
