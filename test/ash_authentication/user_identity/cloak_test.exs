# SPDX-FileCopyrightText: 2026 ash_authentication contributors <https://github.com/team-alembic/ash_authentication/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.UserIdentity.CloakTest do
  @moduledoc false
  use DataCase, async: true

  require Ecto.Query

  defp upsert(attrs) do
    Example.CloakedUserIdentity
    |> Ash.Changeset.for_create(:upsert, attrs)
    |> Ash.create!()
  end

  setup do
    user = build_user()
    uid = "uid-#{System.unique_integer([:positive])}"

    {:ok, user: user, uid: uid}
  end

  test "the tokens are written through cloak and read back", %{user: user, uid: uid} do
    identity =
      upsert(%{
        strategy: "oauth2",
        user_id: user.id,
        user_info: %{"sub" => uid},
        oauth_tokens: %{
          "access_token" => "access-token-value",
          "refresh_token" => "refresh-token-value"
        }
      })

    assert identity.access_token == "access-token-value"
    assert identity.refresh_token == "refresh-token-value"
  end

  test "the stored ciphertext does not contain the plaintext", %{user: user, uid: uid} do
    identity =
      upsert(%{
        strategy: "oauth2",
        user_id: user.id,
        user_info: %{"sub" => uid},
        oauth_tokens: %{"access_token" => "access-token-value"}
      })

    ciphertext =
      Example.CloakedUserIdentity
      |> Ecto.Query.where(id: ^identity.id)
      |> Ecto.Query.select([i], i.encrypted_access_token)
      |> Example.Repo.one!()

    assert is_binary(ciphertext)
    refute ciphertext =~ "access-token-value"
  end

  test "an upsert over an existing identity refreshes the tokens", %{user: user, uid: uid} do
    first =
      upsert(%{
        strategy: "oauth2",
        user_id: user.id,
        user_info: %{"sub" => uid},
        oauth_tokens: %{
          "access_token" => "first-access-token",
          "refresh_token" => "first-refresh-token"
        }
      })

    second =
      upsert(%{
        strategy: "oauth2",
        user_id: user.id,
        user_info: %{"sub" => uid},
        oauth_tokens: %{"access_token" => "second-access-token"}
      })

    assert second.id == first.id
    assert second.access_token == "second-access-token"

    # A missing `refresh_token` must not clear the one already stored.
    assert second.refresh_token == "first-refresh-token"
  end
end
