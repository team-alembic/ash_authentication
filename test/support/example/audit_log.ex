defmodule Example.AuditLog do
  @moduledoc false
  use Ash.Resource,
    data_layer: AshPostgres.DataLayer,
    extensions: [AshAuthentication.AuditLogResource],
    domain: Example

  actions do
    defaults [:read]
  end

  postgres do
    table "audit_logs"
    repo(Example.Repo)
  end
end
