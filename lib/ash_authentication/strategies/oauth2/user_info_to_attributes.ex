# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.UserInfoToAttributes do
  @moduledoc """
  Sets resource attributes from the `user_info` argument provided by an OAuth2 callback.

  Assent normalises all providers to OpenID Connect standard string-keyed fields
  (e.g. `"email"`, `"name"`, `"sub"`), so this change works consistently across providers.

  ## Options

  * `:fields` - a list of attribute atoms to copy from `user_info`. The string key is derived
    from the atom name. Defaults to `[:email]`.

  ## Example

      change {AshAuthentication.Strategy.OAuth2.UserInfoToAttributes, fields: [:email, :name]}
  """

  use Ash.Resource.Change

  @impl true
  def change(changeset, opts, _context) do
    fields = opts[:fields] || [:email]
    user_info = Ash.Changeset.get_argument(changeset, :user_info) || %{}

    Enum.reduce(fields, changeset, fn field, changeset ->
      case Map.get(user_info, to_string(field)) do
        nil -> changeset
        value -> Ash.Changeset.change_attribute(changeset, field, value)
      end
    end)
  end
end
