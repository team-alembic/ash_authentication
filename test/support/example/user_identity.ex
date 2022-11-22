defmodule Example.UserIdentity do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.UserIdentity]

  user_identity do
    api Example
    user_resource(Example.User)
  end

  postgres do
    table "user_identities"
    repo(Example.Repo)
  end
end
