defmodule AshAuthentication.Confirmation.Plug do
  @moduledoc """
  Handlers for incoming HTTP requests.
  """

  import AshAuthentication.Plug.Helpers, only: [private_store: 2]
  alias AshAuthentication.Confirmation
  alias Plug.Conn

  @doc """
  Handle an inbound confirmation request.
  """
  @spec handle(Conn.t(), any) :: Conn.t()
  def handle(%{params: params, private: %{authenticator: config}} = conn, _opts) do
    case Confirmation.confirm(config.resource, params) do
      {:ok, user} ->
        private_store(conn, {:success, user})

      {:error, reason} ->
        private_store(conn, {:failure, reason})
    end
  end
end
