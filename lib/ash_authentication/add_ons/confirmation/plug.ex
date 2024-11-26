defmodule AshAuthentication.AddOn.Confirmation.Plug do
  @moduledoc """
  Handlers for incoming OAuth2 HTTP requests.
  """

  alias AshAuthentication.{AddOn.Confirmation, Strategy}
  alias Plug.Conn
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]
  import Ash.PlugHelpers, only: [get_actor: 1, get_tenant: 1, get_context: 1]

  @doc """
  Attempt to perform a confirmation.
  """
  @spec confirm(Conn.t(), Confirmation.t()) :: Conn.t()
  def confirm(conn, strategy) do
    opts = opts(conn)

    result =
      strategy
      |> Strategy.action(:confirm, conn.params, opts)

    conn
    |> store_authentication_result(result)
  end

  defp opts(conn) do
    [actor: get_actor(conn), tenant: get_tenant(conn), context: get_context(conn) || %{}]
    |> Enum.reject(&is_nil(elem(&1, 1)))
  end
end
