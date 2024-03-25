# defmodule DevServer.GqlRouter do
#   @moduledoc """
#   Router for GraphQL requests.
#   """
#   use Plug.Router
#   import Example.AuthPlug

#   plug(:load_from_bearer)
#   plug(:set_actor, :user)
#   plug(AshGraphql.Plug)
#   plug(:match)
#   plug(:dispatch)

#   forward("/playground",
#     to: Absinthe.Plug.GraphiQL,
#     init_opts: [
#       schema: Example.Schema,
#       interface: :playground
#     ]
#   )

#   forward("/",
#     to: Absinthe.Plug,
#     init_opts: [schema: Example.Schema]
#   )
# end
