# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule SessionPipeline do
  @moduledoc """
  A simple plug pipeline that ensures that the session is set up ready to be consumed.
  """
  use Plug.Builder
  import Ecto.UUID, only: [generate: 0]

  plug(:set_secret)

  plug(Plug.Session,
    store: :cookie,
    key: inspect(__MODULE__),
    encryption_salt: generate(),
    signing_salt: generate()
  )

  plug(:fetch_session)

  @doc false
  def set_secret(conn, _) do
    put_in(conn.secret_key_base, generate() <> generate())
  end
end
