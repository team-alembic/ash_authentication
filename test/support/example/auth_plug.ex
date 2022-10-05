defmodule Example.AuthPlug do
  @moduledoc false
  use AshAuthentication.Plug, otp_app: :ash_authentication

  @impl true
  def handle_success(conn, actor, token) do
    conn
    |> store_in_session(actor)
    |> send_resp(200, """
    Token: #{token}

    Actor: #{inspect(actor)}
    """)
  end

  @impl true
  def handle_failure(conn) do
    conn
    |> send_resp(401, "Sorry mate")
  end
end
