defmodule Example.UserIdentity do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.ProviderIdentity]

  provider_identity do
    api Example
    user_resource(Example.UserWithUsername)
  end

  postgres do
    table "user_identities"
    repo(Example.Repo)
  end
end
