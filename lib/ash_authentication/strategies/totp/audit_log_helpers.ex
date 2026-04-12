# SPDX-FileCopyrightText: 2025 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.AuditLogHelpers do
  @moduledoc """
  Delegates to `AshAuthentication.AddOn.AuditLog.BruteForceHelpers`.

  Kept for backwards compatibility.
  """

  defdelegate count_failures(audit_log, subject, strategy_name, cutoff),
    to: AshAuthentication.AddOn.AuditLog.BruteForceHelpers

  @doc false
  def count_failures(audit_log, subject, cutoff) do
    count_failures(audit_log, subject, :totp, cutoff)
  end
end
