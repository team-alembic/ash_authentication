# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.OAuth2EmailChange do
  @moduledoc false
  use Ash.Resource.Change
  alias Ash.{Changeset, Resource.Change}

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, _context) do
    user_info = Changeset.get_argument(changeset, :user_info)

    case user_info["email"] do
      nil -> changeset
      email -> Changeset.change_attribute(changeset, :email, email)
    end
  end
end
