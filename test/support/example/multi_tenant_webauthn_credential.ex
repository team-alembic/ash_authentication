# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.MultiTenantWebAuthnCredential do
  @moduledoc false
  use Ash.Resource,
    domain: Example,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshAuthentication.WebAuthnCredential]

  webauthn_credential do
    user_resource Example.MultiTenantUserWithWebAuthn
  end

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

  # Attributes, the `belongs_to :user`, the unique identity and the CRUD
  # actions are all built by the `WebAuthnCredential` extension.
  attributes do
    uuid_primary_key :id
    create_timestamp :inserted_at
    update_timestamp :updated_at
  end
end
