defmodule Example.Token do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.TokenResource],
    domain: Example

  postgres do
    table("tokens")
    repo(Example.Repo)
  end
end
