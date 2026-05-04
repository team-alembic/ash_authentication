# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.OidcConnection.Info do
  @moduledoc """
  Introspection functions for the `AshAuthentication.OidcConnection` Ash
  extension.
  """

  use Spark.InfoGenerator,
    extension: AshAuthentication.OidcConnection,
    sections: [:oidc_connection]
end
