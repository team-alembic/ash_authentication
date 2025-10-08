# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.RememberMe.SignInPreparationTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias AshAuthentication.Strategy.RememberMe
  alias AshAuthentication.Strategy.RememberMe.SignInPreparation
  alias Example.UserWithRememberMe

  use Mimic

  describe "prepare/3" do
    test "sets up before_action and after_action" do
      query = %Ash.Query{resource: UserWithRememberMe}
      options = []
      context = %{}

      AshAuthentication.Info
      |> expect(:find_strategy, fn ^query, ^context, ^options -> {:ok, %RememberMe{}} end)

      assert %{before_action: [_prepare], after_action: [_verify]} =
               SignInPreparation.prepare(query, options, context)
    end
  end
end
