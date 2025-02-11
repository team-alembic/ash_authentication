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

  actions do
    defaults [:read, :destroy]

    action :revoked? do
      description "Returns true if a revocation token is found for the provided token"
      argument :token, :string, sensitive?: true
      argument :jti, :string, sensitive?: true

      run AshAuthentication.TokenResource.IsRevoked
      returns :boolean
    end
  end
end
