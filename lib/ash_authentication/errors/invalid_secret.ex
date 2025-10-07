# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Errors.InvalidSecret do
  @moduledoc """
  A secret returned an invalid value.
  """
  use Splode.Error, fields: [:resource, :value], class: :forbidden

  def message(%{path: path, resource: resource}) do
    "Secret for `#{Enum.join(path, ".")}` on the `#{inspect(resource)}` resource returned an invalid value. Expected an `:ok` tuple, or `:error`."
  end
end
