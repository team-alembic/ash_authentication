defmodule ExampleStateless.Token do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.TokenResource],
    domain: ExampleStateless

  postgres do
    table "stateless_token"
    repo(Example.Repo)
  end

  # The token resource for the stateless user
end
