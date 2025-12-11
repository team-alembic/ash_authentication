# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.TotpNoopPreparation do
  @moduledoc """
  A no-operation preparation for TOTP brute force protection.

  This is for testing purposes only.
  """
  use Ash.Resource.Preparation

  @doc false
  @impl true
  def supports(_opts), do: [Ash.Query, Ash.ActionInput]

  @doc false
  @impl true
  def prepare(query, _opts, _context) when is_struct(query, Ash.Query), do: query
  def prepare(input, _opts, _context) when is_struct(input, Ash.ActionInput), do: input
end
