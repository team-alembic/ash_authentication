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
  def supports(_opts), do: [Ash.Query, Ash.ActionInput, Ash.Changeset]

  @doc false
  @impl true
  def prepare(query_or_input, _opts, _context), do: query_or_input
end
