# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# Stub module so that Code.ensure_loaded?(AshAuthentication.Phoenix) returns
# true during tests. This allows the TOTP generator's Phoenix integration
# branch to be exercised without introducing a circular dependency on the
# real ash_authentication_phoenix package.
unless Code.ensure_loaded?(AshAuthentication.Phoenix) do
  defmodule AshAuthentication.Phoenix do
    @moduledoc false
  end
end
