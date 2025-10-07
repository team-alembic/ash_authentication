# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.TokenResource.RevokeAllStoredForSubjectChange do
  @moduledoc """
  Updates all tokens for a given subject to have the purpose revocation
  """

  use Ash.Resource.Change
  alias Ash.{Changeset, Resource.Change}

  @doc false
  @impl true
  def atomic(changeset, opts, context) do
    {:ok, change(changeset, opts, context)}
  end

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, _context) do
    changeset
    |> Ash.Changeset.filter(expr(subject == ^changeset.arguments.subject))
    |> Changeset.change_attributes(purpose: "revocation")
  end
end
