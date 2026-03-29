defmodule Example.MultiTenantWebAuthnCredential do
  @moduledoc false
  use Ash.Resource,
    domain: Example,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer]

  postgres do
    table "mt_webauthn_credentials"
    repo(Example.Repo)
  end

  multitenancy do
    strategy :context
  end

  policies do
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end

    policy always() do
      authorize_if always()
    end
  end

  attributes do
    uuid_primary_key :id
    attribute :credential_id, :binary, allow_nil?: false, public?: true

    attribute :public_key, AshAuthentication.Strategy.WebAuthn.CoseKey,
      allow_nil?: false,
      public?: true

    attribute :sign_count, :integer, default: 0, allow_nil?: false, public?: true
    attribute :label, :string, default: "Security Key", public?: true
    attribute :last_used_at, :utc_datetime_usec, public?: true
    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  relationships do
    belongs_to :user, Example.MultiTenantUserWithWebAuthn, allow_nil?: false, public?: true
  end

  identities do
    identity :unique_credential_id, [:credential_id]
  end

  actions do
    defaults [:read, :destroy]

    create :create do
      primary? true
      accept [:credential_id, :public_key, :sign_count, :label, :user_id]
    end

    update :update do
      primary? true
      accept [:sign_count, :label, :last_used_at]
    end
  end
end
