defmodule Example.AuthPlug do
  @moduledoc false
  use AshAuthentication.Plug, otp_app: :ash_authentication

  @impl true
  def handle_success(conn, user, token) do
    conn
    |> store_in_session(user)
    |> send_resp(200, """
    Token: #{token}

    User: #{inspect(user)}
    """)
  end

  @impl true
  def handle_failure(conn, _) do
    conn
    |> send_resp(401, "Sorry mate")
  end
end
