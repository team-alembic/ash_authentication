# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UnstoredWebAuthnCredential do
  @moduledoc false
  use Ash.Resource,
    domain: Example,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.WebAuthnCredential]

  webauthn_credential do
    user_resource Example.UserWithUnstoredWebAuthn
  end

  postgres do
    table "unstored_webauthn_credentials"
    repo(Example.Repo)
  end

  attributes do
    uuid_primary_key :id
    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  relationships do
    belongs_to :user, Example.UserWithUnstoredWebAuthn, allow_nil?: false, public?: true
  end
end
