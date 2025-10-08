# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule ExampleMultiTenant.Organisation do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    domain: ExampleMultiTenant

  postgres do
    table("mt_organisations")
    repo(Example.Repo)
  end

  actions do
    defaults [:read, create: :*]
  end

  multitenancy do
    strategy :attribute
    attribute :id
    global? true
  end

  attributes do
    uuid_primary_key(:id, writable?: true)

    attribute(:name, :ci_string, allow_nil?: false, public?: true)

    create_timestamp(:created_at)
    update_timestamp(:updated_at)
  end
end
