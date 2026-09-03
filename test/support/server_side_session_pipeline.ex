# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule ServerSideSessionPipeline do
  @moduledoc """
  Sets up a session backed by an ETS store, so that tests can assert on the
  session identifier.

  The cookie store keeps the whole session inside the cookie and has no
  identifier of its own, so it cannot show whether a session was renewed. A
  server-side store puts only an identifier in the cookie, which is the value
  these tests compare across the authentication boundary.
  """

  import Plug.Conn
  import Ecto.UUID, only: [generate: 0]

  @cookie_key "_ash_authentication_test_session"

  @doc "The name of the cookie holding the session identifier."
  @spec cookie_key :: String.t()
  def cookie_key, do: @cookie_key

  @doc "Build a fresh ETS session store, isolated to the calling test."
  @spec new_store :: :ets.table()
  def new_store, do: :ets.new(:ash_authentication_test_session, [:set, :public])

  @doc "Fetch the session for `conn`, backed by `store`."
  @spec call(Plug.Conn.t(), :ets.table()) :: Plug.Conn.t()
  def call(conn, store) do
    opts = Plug.Session.init(store: :ets, key: @cookie_key, table: store)

    conn
    |> put_in([Access.key!(:secret_key_base)], generate() <> generate())
    |> Plug.Session.call(opts)
    |> fetch_session()
  end

  @doc """
  The session identifier `conn` sends back to the browser.

  `Plug.Session` writes the session on `before_send`, so the response has to be
  sent before the identifier can be read.
  """
  @spec sent_session_id(Plug.Conn.t()) :: String.t() | nil
  def sent_session_id(conn) do
    conn = send_resp(conn, 200, "")

    case conn.resp_cookies[@cookie_key] do
      %{value: value} -> value
      nil -> nil
    end
  end
end
