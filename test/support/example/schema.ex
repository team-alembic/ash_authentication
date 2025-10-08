# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.Schema do
  @moduledoc false
  use Absinthe.Schema

  use AshGraphql, domains: [Example]

  query do
  end
end
