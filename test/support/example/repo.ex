# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.Repo do
  @moduledoc false
  use AshPostgres.Repo, otp_app: :ash_authentication

  @doc false
  def installed_extensions, do: ["ash-functions", "uuid-ossp", "citext"]

  @doc false
  def min_pg_version do
    %Version{major: 16, minor: 0, patch: 0}
  end
end
