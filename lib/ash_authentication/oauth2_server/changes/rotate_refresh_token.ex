# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Oauth2Server.Changes.RotateRefreshToken do
  @moduledoc """
  Change that rotates a refresh-token row atomically.

  Attaches a filter expression — `is_nil(rotated_to_id) and is_nil(revoked_at)`
  — to the changeset so the underlying `UPDATE` only matches a row that's
  still valid AND unrotated AND unrevoked. The `:rotated_to_id` argument
  is then written to the row.

  A concurrent rotation race produces one winner; the loser's UPDATE
  matches zero rows and the `Token` core treats it as `:reuse`, triggering
  chain revocation per OAuth 2.1 §4.3.1.

  Usage in your refresh-token resource:

      update :rotate do
        argument :rotated_to_id, :uuid_v7, allow_nil?: false
        accept []
        require_atomic? false

        change AshAuthentication.Oauth2Server.Changes.RotateRefreshToken
      end
  """

  use Ash.Resource.Change

  require Ash.Expr

  @impl true
  def change(changeset, _opts, _context) do
    new_id = Ash.Changeset.get_argument(changeset, :rotated_to_id)

    changeset
    |> Ash.Changeset.filter(Ash.Expr.expr(is_nil(rotated_to_id) and is_nil(revoked_at)))
    |> Ash.Changeset.force_change_attribute(:rotated_to_id, new_id)
  end

  @impl true
  def atomic(changeset, opts, context) do
    {:ok, change(changeset, opts, context)}
  end
end
