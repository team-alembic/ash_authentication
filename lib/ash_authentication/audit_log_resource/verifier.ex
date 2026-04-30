# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AuditLogResource.Verifier do
  @moduledoc """
  Compile-time checks for the audit log resource.
  """

  use Spark.Dsl.Verifier
  alias Spark.Dsl.Verifier
  import AshAuthentication.Validations, only: [warn_if_data_layer_cannot_lock: 2]

  @doc false
  @impl true
  @spec verify(map) :: :ok | {:error, term}
  def verify(dsl_state) do
    warn_if_data_layer_cannot_lock(
      Verifier.get_persisted(dsl_state, :module),
      "Brute-force protection counts failed attempts inside a `SELECT ... FOR UPDATE` window so concurrent attempts can't slip past the threshold."
    )
  end
end
