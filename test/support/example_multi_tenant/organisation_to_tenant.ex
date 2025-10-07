# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule ExampleMultiTenant.Organisation.ToTenant do
  @moduledoc """
  Implementation of Ash.ToTenant protocol for Organisation.
  Converts Organisation struct to tenant identifier for schema-based multitenancy.
  """

  defimpl Ash.ToTenant, for: ExampleMultiTenant.Organisation do
    def to_tenant(%{id: id}, _resource) do
      id
    end
  end
end
