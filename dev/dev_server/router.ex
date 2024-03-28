defmodule DevServer.Router do
  @moduledoc false
  use Plug.Router

  plug(Plug.Parsers, parsers: [:urlencoded, :multipart, :json], json_decoder: Jason)
  plug(Plug.Session, store: :ets, key: "_ash_authentication_session", table: DevServer.Session)
  plug(:fetch_session)
  plug(:fetch_query_params)
  plug(Plug.Logger)
  plug(:match)
  plug(:dispatch)

  forward("/auth", to: Example.AuthPlug)
  get("/clear_session", to: DevServer.ClearSession)
  post("/token_check", to: DevServer.TokenCheck)
  # forward("/api", to: DevServer.ApiRouter)
  # forward("/gql", to: DevServer.GqlRouter)
  forward("/", to: DevServer.WebRouter)
end
