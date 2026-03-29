defmodule Example.WebAuthnCredential do
  @moduledoc false
  use Ash.Resource,
    domain: Example,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer]

  postgres do
    table "webauthn_credentials"
    repo(Example.Repo)
  end

  # IMPORTANT: This bypass policy allows AshAuthentication's internal
  # operations (store credential, update sign count, etc.) to work.
  # Without it, any credential resource with policies will reject all
  # internal operations because they set the ash_authentication? context flag.
  policies do
    bypass AshAuthentication.Checks.AshAuthenticationInteraction do
      authorize_if always()
    end

    # Allow read/destroy for the credential owner (example policy)
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
    belongs_to :user, Example.UserWithWebAuthn, allow_nil?: false, public?: true
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
