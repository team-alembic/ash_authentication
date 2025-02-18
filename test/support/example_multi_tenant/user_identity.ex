defmodule ExampleMultiTenant.UserIdentity do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.UserIdentity],
    domain: ExampleMultiTenant

  user_identity do
    user_resource(ExampleMultiTenant.User)
  end

  postgres do
    table("mt_user_identities")
    repo(Example.Repo)
  end

  relationships do
    belongs_to :organisation, ExampleMultiTenant.Organisation
  end
end
