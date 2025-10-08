# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.BcryptProviderTest do
  @moduledoc false
  use ExUnit.Case, async: true
  import AshAuthentication.BcryptProvider
  doctest AshAuthentication.BcryptProvider
end
