defmodule DevServer.WebRouter do
  @moduledoc """
  Router for web (browser) requests.
  """
  use Plug.Router
  import Example.AuthPlug

  plug(:load_from_session)
  plug(:match)
  plug(:dispatch)

  get("/", to: DevServer.TestPage)

  match _ do
    send_resp(conn, 404, "NOT FOUND")
  end
end
