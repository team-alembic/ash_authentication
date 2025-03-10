defmodule DevServer.TokenCheck do
  @moduledoc """
  Verifies a submitted token and reports the contents.
  """

  @behaviour Plug
  alias AshAuthentication.Jwt
  alias Plug.Conn

  @doc false
  @impl true
  @spec init(keyword) :: keyword
  def init(opts), do: opts

  @doc false
  @impl true
  @spec call(Conn.t(), any) :: Conn.t()
  def call(%{params: %{"token" => token}} = conn, _opts) do
    result = Jwt.verify(token, :ash_authentication, %{conn: conn})

    conn
    |> Conn.send_resp(200, inspect(result))
  end

  def call(conn, _opts), do: Conn.send_resp(conn, 200, "Invalid request")
end
