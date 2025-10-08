# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.UtilsTest do
  @moduledoc false
  use ExUnit.Case, async: true
  alias AshAuthentication.Utils

  describe "lifetime_to_seconds/1" do
    test "converts integer seconds to seconds" do
      assert Utils.lifetime_to_seconds(30) == 30
      assert Utils.lifetime_to_seconds(0) == 0
      assert Utils.lifetime_to_seconds(3600) == 3600
      assert Utils.lifetime_to_seconds({3600, :seconds}) == 3600
      assert Utils.lifetime_to_seconds({60, :minutes}) == 3600
      assert Utils.lifetime_to_seconds({24, :hours}) == 86_400
      assert Utils.lifetime_to_seconds({365, :days}) == 31_536_000
    end
  end
end
