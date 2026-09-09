# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.OAuthAuditLogUserIdentity do
  @moduledoc """
  Identity resource for `Example.UserWithOAuthAuditLog`.
  """
  use Ash.Resource,
    data_layer: Ash.DataLayer.Ets,
    extensions: [AshAuthentication.UserIdentity],
    domain: Example

  user_identity do
    user_resource(Example.UserWithOAuthAuditLog)
  end

  identities do
    identity :unique_on_strategy_and_uid, [:uid, :strategy], pre_check_with: Example
  end
end
