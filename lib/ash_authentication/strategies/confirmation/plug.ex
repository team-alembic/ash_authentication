defmodule AshAuthentication.Strategy.Confirmation.Plug do
  @moduledoc """
  Handlers for incoming OAuth2 HTTP requests.
  """

  alias AshAuthentication.{Strategy, Strategy.Confirmation}
  alias Plug.Conn
  import AshAuthentication.Plug.Helpers, only: [store_authentication_result: 2]

  @doc """
  Attempt to perform a confirmation.
  """
  @spec confirm(Conn.t(), Confirmation.t()) :: Conn.t()
  def confirm(conn, strategy) do
    result =
      strategy
      |> Strategy.action(:confirm, conn.params)

    conn
    |> store_authentication_result(result)
  end
end
