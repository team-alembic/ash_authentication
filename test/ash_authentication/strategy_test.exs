# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.StrategyTest do
  @moduledoc false
  use DataCase, async: true
  alias AshAuthentication.Info
  import AshAuthentication.Strategy
  doctest AshAuthentication.Strategy
end
