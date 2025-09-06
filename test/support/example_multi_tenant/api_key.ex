defmodule ExampleMultiTenant.ApiKey do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    domain: ExampleMultiTenant

  attributes do
    uuid_primary_key :id

    attribute :api_key_hash, :binary, allow_nil?: false, public?: true
    attribute :expires_at, :utc_datetime_usec, allow_nil?: false

    create_timestamp :created_at
    update_timestamp :updated_at
  end

  calculations do
    calculate :valid, :boolean, expr(expires_at > now())
  end

  relationships do
    belongs_to :user, ExampleMultiTenant.User do
      public? true
      attribute_writable? true
      primary_key? true
      allow_nil? false
    end

    belongs_to :global_user, ExampleMultiTenant.GlobalUser do
      public? true
      attribute_writable? true
      allow_nil? true
    end

    belongs_to :organisation, ExampleMultiTenant.Organisation do
      public? true
      attribute_writable? true
      allow_nil? false
    end
  end

  postgres do
    table "mt_api_keys"
    repo(Example.Repo)
  end

  multitenancy do
    strategy :attribute
    attribute :organisation_id
    global? true
  end

  policies do
    bypass always() do
      authorize_if AshAuthentication.Checks.AshAuthenticationInteraction
    end
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      primary? true
      accept [:user_id, :global_user_id, :organisation_id, :expires_at]

      change {AshAuthentication.Strategy.ApiKey.GenerateApiKey,
              prefix: :mtaap, hash: :api_key_hash}
    end
  end
end
