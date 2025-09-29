defmodule AshAuthentication.AuditLogResource.Info do
  @moduledoc """
  Introspection functions for the `AshAuthentication.AuditLogResource` Ash extension.
  """
  use Spark.InfoGenerator, extension: AshAuthentication.AuditLogResource, sections: [:audit_log]
end
