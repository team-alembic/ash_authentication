# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule DevServer.Session do
  @moduledoc """
  Does nothing but own an ETS table for the session to be stored in.
  """

  use GenServer

  @doc false
  def start_link(opts), do: GenServer.start_link(__MODULE__, opts, [])

  @doc false
  @impl true
  def init(_) do
    table_ref = :ets.new(__MODULE__, [:named_table, :public, read_concurrency: true])
    {:ok, table_ref, :hibernate}
  end
end
