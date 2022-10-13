defmodule DevServer.ClearSession do
  @moduledoc """
  Resets the session storage, to 'log out" all actors.
  """

  @behaviour Plug
  alias Plug.Conn

  @doc false
  @impl true
  @spec init(keyword) :: keyword
  def init(opts), do: opts

  @doc false
  @impl true
  @spec call(Conn.t(), any) :: Conn.t()
  def call(conn, _opts) do
    conn
    |> Conn.clear_session()
    |> Conn.put_resp_header("location", "/")
    |> Conn.send_resp(302, "Redirected")
  end
end
