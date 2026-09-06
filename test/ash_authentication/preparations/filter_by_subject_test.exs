# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Preparations.FilterBySubjectTest do
  @moduledoc false
  use DataCase, async: true

  alias Ash.Error.Query.NotFound

  describe "subject validation" do
    test "it rejects a subject minted for a different resource" do
      {user, other_user} = build_colliding_users()

      assert {:error, %{errors: [%NotFound{}]}} =
               get_by_subject("user_with_remember_me?id=#{other_user.id}")

      assert user.id == other_user.id
    end

    test "it rejects a subject which names a non-primary-key field" do
      user = build_user()

      assert {:error, %{errors: [%NotFound{}]}} =
               get_by_subject("user?username=#{user.username}")
    end

    test "it rejects a subject with an empty query, even when only one user exists" do
      build_user()

      assert {:error, %{errors: [%NotFound{}]}} = get_by_subject("user?")
    end
  end

  defp get_by_subject(subject) do
    Example.User
    |> Ash.Query.new()
    |> Ash.Query.for_read(:get_by_subject, %{subject: subject})
    |> Ash.read_one(not_found_error?: true)
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
