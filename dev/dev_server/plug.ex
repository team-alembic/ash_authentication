defmodule DevServer.Plug do
  @moduledoc false
  use Plug.Router
  alias DevServer
  import Example.AuthPlug

  plug(Plug.Parsers, parsers: [:urlencoded, :multipart, :json], json_decoder: Jason)
  plug(Plug.Session, store: :ets, key: "_ash_authentication_session", table: DevServer.Session)
  plug(:fetch_query_params)
  plug(:fetch_session)
  plug(Plug.Logger)
  plug(:load_from_session)
  plug(:match)
  plug(:dispatch)

  forward("/auth", to: Example.AuthPlug.Router)
  get("/clear_session", to: DevServer.ClearSession)
  post("/token_check", to: DevServer.TokenCheck)
  get("/", to: DevServer.TestPage)

  match _ do
    send_resp(conn, 404, "NOT FOUND")
  end
end
