defmodule AshAuthExampleWeb.PageController do
  @moduledoc false
  use AshAuthExampleWeb, :controller

  @doc false
  @spec index(Plug.Conn.t(), map) :: Plug.Conn.t()
  def index(conn, _params) do
    render(conn, "index.html")
  end
end
