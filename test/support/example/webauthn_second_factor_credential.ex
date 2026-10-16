# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.WebAuthnSecondFactorCredential do
  @moduledoc false
  use Ash.Resource,
    domain: Example,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.WebAuthnCredential]

  webauthn_credential do
    user_resource Example.UserWithWebAuthnSecondFactor
  end

  postgres do
    table "webauthn_second_factor_credentials"
    repo(Example.Repo)
  end

  attributes do
    uuid_primary_key :id
    create_timestamp :inserted_at
    update_timestamp :updated_at
  end

  relationships do
    belongs_to :user, Example.UserWithWebAuthnSecondFactor, allow_nil?: false, public?: true
  end
end
