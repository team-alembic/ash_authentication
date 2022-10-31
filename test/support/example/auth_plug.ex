defmodule Example.AuthPlug do
  @moduledoc false
  use AshAuthentication.Plug, otp_app: :ash_authentication

  @impl true
  def handle_success(conn, user, token) do
    conn
    |> store_in_session(user)
    |> put_resp_header("content-type", "application/json")
    |> send_resp(
      200,
      Jason.encode!(%{
        token: token,
        user: %{
          id: user.id,
          username: user.username
        }
      })
    )
  end

  @impl true
  def handle_failure(conn, reason) do
    conn
    |> put_resp_header("content-type", "application/json")
    |> send_resp(
      401,
      Jason.encode!(%{
        status: "failed",
        reason: inspect(reason)
      })
    )
  end
end
