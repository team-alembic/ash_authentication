# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Example.AuditLogNoExpiry do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.AuditLogResource],
    domain: Example

  audit_log do
    log_lifetime :infinity
  end

  actions do
    defaults [:read]
  end

  postgres do
    table "audit_logs_no_expiry"
    repo(Example.Repo)
  end
end
