defmodule AshAuthentication.Plug.Defaults do
  @moduledoc """
  Provides the default implementations of `handle_success/3` and
  `handle_failure/2` used in generated authentication plugs.
  """

  alias Ash.Resource
  alias Plug.Conn
  import AshAuthentication.Plug.Helpers
  import Plug.Conn

  @doc """
  The default implementation of `handle_success/3`.

  Calls `AshAuthentication.Plug.Helpers.store_in_session/2` then sends a
  basic 200 response.
  """
  @spec handle_success(Conn.t(), {atom, atom}, Resource.record() | nil, String.t() | nil) ::
          Conn.t()
  def handle_success(conn, _activity, user, _token) do
    conn
    |> store_in_session(user)
    |> send_resp(200, "Access granted")
  end

  @doc """
  The default implementation of `handle_failure/1`.

  Sends a very basic 401 response.
  """
  @spec handle_failure(Conn.t(), {atom, atom}, any) :: Conn.t()
  def handle_failure(conn, _, _) do
    conn
    |> send_resp(401, "Access denied")
  end
end
