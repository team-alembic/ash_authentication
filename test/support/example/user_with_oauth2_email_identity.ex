# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.UserWithOauth2EmailIdentity do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.UserIdentity],
    domain: Example

  user_identity do
    user_resource(Example.UserWithOauth2Email)
  end

  postgres do
    table "oauth2_email_user_identities"
    repo(Example.Repo)
  end
end
