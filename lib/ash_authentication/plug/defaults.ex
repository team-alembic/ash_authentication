defmodule AshAuthentication.Plug.Defaults do
  @moduledoc """
  Provides the default implementations of `handle_success/3` and
  `handle_failure/2` used in generated authentication plugs.
  """

  alias Ash.{Changeset, Error, Resource}
  alias Plug.Conn
  import AshAuthentication.Plug.Helpers
  import Plug.Conn

  @doc """
  The default implementation of `handle_success/3`.

  Calls `AshAuthentication.Plug.Helpers.store_in_session/2` then sends a
  basic 200 response.
  """
  @spec handle_success(Conn.t(), Resource.record(), token :: String.t()) ::
          Conn.t()
  def handle_success(conn, user, _token) do
    conn
    |> store_in_session(user)
    |> send_resp(200, "Access granted")
  end

  @doc """
  The default implementation of `handle_failure/1`.

  Sends a very basic 401 response.
  """
  @spec handle_failure(Conn.t(), nil | Changeset.t() | Error.t()) :: Conn.t()
  def handle_failure(conn, _) do
    conn
    |> send_resp(401, "Access denied")
  end
end
