defmodule DevServer.ApiRouter do
  @moduledoc """
  Router for API Requests.
  """
  use Plug.Router
  import Example.AuthPlug

  plug(:load_from_bearer)
  plug(:set_actor, :user)
  plug(:match)
  plug(:dispatch)

  forward("/", to: DevServer.JsonApiRouter)
end
