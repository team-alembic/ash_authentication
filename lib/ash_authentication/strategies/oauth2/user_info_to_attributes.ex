# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.UserInfoToAttributes do
  @moduledoc """
  Sets resource attributes from the `user_info` argument provided by an OAuth2 callback.

  Assent normalises all providers to OpenID Connect standard string-keyed fields
  (e.g. `"email"`, `"name"`, `"sub"`), so this change works consistently across providers.

  ## Options

  * `:fields` - a list of fields to copy from `user_info`. Each entry can be:
    * An atom (e.g. `:email`) — maps `"email"` from user_info to the `:email` attribute
    * A `{source, attribute}` tuple (e.g. `{:email, :user_email}`) — maps `"email"` from
      user_info to the `:user_email` attribute

    Defaults to `[:email]`.

  ## Examples

      change {AshAuthentication.Strategy.OAuth2.UserInfoToAttributes, fields: [:email, :name]}

      change {AshAuthentication.Strategy.OAuth2.UserInfoToAttributes, fields: [email: :user_email]}
  """

  use Ash.Resource.Change

  @impl true
  def change(changeset, opts, _context) do
    fields = opts[:fields] || [:email]
    user_info = Ash.Changeset.get_argument(changeset, :user_info) || %{}

    Enum.reduce(fields, changeset, fn field_spec, changeset ->
      {source, attribute} = normalize_field(field_spec)

      case Map.get(user_info, to_string(source)) do
        nil -> changeset
        value -> Ash.Changeset.change_attribute(changeset, attribute, value)
      end
    end)
  end

  defp normalize_field({source, attribute}) when is_atom(source) and is_atom(attribute),
    do: {source, attribute}

  defp normalize_field(field) when is_atom(field),
    do: {field, field}
end
