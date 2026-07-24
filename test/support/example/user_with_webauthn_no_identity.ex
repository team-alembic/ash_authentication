# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithWebAuthnNoIdentity do
  @moduledoc false
  # Passkey-first fixture: no email-style attribute, no unique identity.
  # Users are resolved from the WebAuthn credential id alone.
  use Ash.Resource,
    domain: Example,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication]

  postgres do
    table "user_with_webauthn_no_identity"
    repo(Example.Repo)
  end

  attributes do
    uuid_primary_key :id
    create_timestamp :created_at
    update_timestamp :updated_at
  end

  actions do
    defaults [:read]

    create :create do
    end
  end

  relationships do
    has_many :webauthn_credentials, Example.WebAuthnNoIdentityCredential,
      destination_attribute: :user_id
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
        require_identity? false
        credential_resource(Example.WebAuthnNoIdentityCredential)
        rp_id("example.com")
        rp_name("Test App")
        origin("https://example.com")
      end
    end
  end
end
