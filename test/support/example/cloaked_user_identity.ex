# SPDX-FileCopyrightText: 2026 ash_authentication contributors <https://github.com/team-alembic/ash_authentication/graphs/contributors>
#
# SPDX-License-Identifier: MIT

defmodule Example.CloakedUserIdentity do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.UserIdentity, AshCloak],
    domain: Example

  cloak do
    vault(Example.Vault)
    attributes([:access_token, :refresh_token])
    decrypt_by_default([:access_token, :refresh_token])
  end

  user_identity do
    user_resource Example.User
  end

  postgres do
    table "cloaked_user_identities"
    repo(Example.Repo)
  end
end
