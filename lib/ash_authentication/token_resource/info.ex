# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.TokenResource.Info do
  @moduledoc """
  Introspection functions for the `AshAuthentication.TokenResource` Ash
  extension.
  """

  use Spark.InfoGenerator,
    extension: AshAuthentication.TokenResource,
    sections: [:token]
end
