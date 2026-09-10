# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Test.PermissiveDomain do
  @moduledoc """
  A domain that accepts any resource, for tests that dynamically compile
  throwaway resources and don't want to register them anywhere.
  """
  use Ash.Domain

  resources do
    allow_unregistered?(true)
  end
end
