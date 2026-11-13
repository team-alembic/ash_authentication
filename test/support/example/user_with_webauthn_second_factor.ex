# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithWebAuthnSecondFactor do
  @moduledoc """
  WebAuthn as a second factor only: users register and sign in with a
  password, and the `webauthn` strategy exposes nothing but the `verify` and
  `add_credential` ceremonies on top of that session.

  This is the configuration `mix ash_authentication.add_strategy.webauthn
  --mode 2fa` generates.
  """
  use Ash.Resource,
    domain: Example,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication]

  postgres do
    table "user_with_webauthn_second_factor"
    repo(Example.Repo)
  end

  attributes do
    uuid_primary_key :id
    attribute :email, :ci_string, allow_nil?: false, public?: true
    attribute :hashed_password, :string, allow_nil?: true, sensitive?: true, public?: false
    create_timestamp :created_at
    update_timestamp :updated_at
  end

  actions do
    defaults [:read]
  end

  relationships do
    has_many :webauthn_credentials, Example.WebAuthnSecondFactorCredential,
      destination_attribute: :user_id
  end

  identities do
    identity :unique_email, [:email]
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
      password :password do
        identity_field :email
      end

      webauthn :webauthn do
        credential_resource(Example.WebAuthnSecondFactorCredential)
        rp_id("example.com")
        rp_name("Test App")
        identity_field :email
        registration_enabled? false
        sign_in_enabled? false
      end
    end
  end
end
