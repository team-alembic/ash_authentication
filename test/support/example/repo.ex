# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.Repo do
  @moduledoc false
  use AshPostgres.Repo, otp_app: :ash_authentication

  @doc false
  @impl AshPostgres.Repo
  def installed_extensions, do: ["ash-functions", "uuid-ossp", "citext"]

  # Schema-based (`strategy :context`) multitenant resources create one Postgres
  # schema per tenant. Tenant migrations (and codegen's dev-migration cleanup)
  # need the list of those schemas — every schema that isn't a Postgres/system
  # one is a tenant schema in this test database.
  @doc false
  @impl AshPostgres.Repo
  def all_tenants do
    __MODULE__
    |> Ecto.Adapters.SQL.query!(
      "SELECT schema_name FROM information_schema.schemata " <>
        "WHERE schema_name NOT IN ('public', 'information_schema') " <>
        "AND schema_name NOT LIKE 'pg\\_%'",
      []
    )
    |> Map.fetch!(:rows)
    |> List.flatten()
  end

  @doc false
  @impl AshPostgres.Repo
  def min_pg_version do
    %Version{major: 16, minor: 0, patch: 0}
  end
end
