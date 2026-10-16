# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.WebAuthnCredential do
  @moduledoc false
  use Ash.Resource,
    domain: Example,
    data_layer: AshPostgres.DataLayer,
    authorizers: [Ash.Policy.Authorizer],
    extensions: [AshAuthentication.WebAuthnCredential]

  webauthn_credential do
    user_resource Example.UserWithWebAuthn
  end

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
    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  relationships do
    belongs_to :user, Example.UserWithWebAuthn, allow_nil?: false, public?: true
  end
end
