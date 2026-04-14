defmodule Example.UserWithWebAuthn do
  @moduledoc false
  use Ash.Resource,
    domain: Example,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication]

  postgres do
    table "user_with_webauthn"
    repo(Example.Repo)
  end

  attributes do
    uuid_primary_key :id
    attribute :email, :ci_string, allow_nil?: false, writable?: true, public?: true
    create_timestamp :created_at
    update_timestamp :updated_at
  end

  actions do
    defaults [:read]

    create :create do
      accept [:email]
    end
  end

  relationships do
    has_many :webauthn_credentials, Example.WebAuthnCredential, destination_attribute: :user_id
  end

  identities do
    identity :unique_email_webauthn, [:email]
  end

  authentication do
    session_identifier(:jti)

    tokens do
      enabled? true
      store_all_tokens? true
      token_resource Example.Token
      signing_secret &Example.User.get_config/2
    end

    strategies do
      webauthn :webauthn do
        credential_resource(Example.WebAuthnCredential)
        rp_id("example.com")
        rp_name("Test App")
        origin("https://example.com")
        identity_field :email
      end
    end
  end
end
