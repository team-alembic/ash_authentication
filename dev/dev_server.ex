# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule DevServer do
  @moduledoc """
  This module provides an extremely simplified authentication UI, mainly for
  local development and testing.
  """

  use Supervisor

  def start_link(init_arg), do: Supervisor.start_link(__MODULE__, init_arg, name: __MODULE__)

  @impl true
  def init(_init_arg) do
    opts =
      :ash_authentication
      |> Application.get_env(DevServer, [])
      |> Keyword.delete(:start?)

    [
      {DevServer.Session, []},
      {Plug.Cowboy, scheme: :http, plug: DevServer.Router, options: opts}
    ]
    |> Supervisor.init(strategy: :one_for_all)
  end
end
