defmodule Example.UserIdentity do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.UserIdentity],
    domain: Example

  user_identity do
    user_resource(Example.User)
  end

  postgres do
    table "user_identities"
    repo(Example.Repo)
  end
end
