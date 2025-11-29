# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenChangeTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenChange
  alias Example.UserWithRememberMe

  describe "prepare/3" do
    test "returns changeset unchanged when remember_me argument is false" do
      changeset =
        UserWithRememberMe
        |> Ash.Changeset.new()
        |> Ash.Changeset.set_argument(:remember_me, false)

      options = []
      context = %{}

      result = MaybeGenerateTokenChange.change(changeset, options, context)
      assert result == changeset
    end

    test "returns changeset unchanged when remember_me argument is nil" do
      changeset =
        UserWithRememberMe
        |> Ash.Changeset.new()
        |> Ash.Changeset.set_argument(:remember_me, nil)

      options = []
      context = %{}

      result = MaybeGenerateTokenChange.change(changeset, options, context)
      assert result == changeset
    end

    test "calls changeset_after_action when remember_me argument is true" do
      changeset =
        UserWithRememberMe
        |> Ash.Changeset.new()
        |> Ash.Changeset.set_argument(:remember_me, true)

      options = []
      context = %{}

      assert %Ash.Changeset{after_action: [_changeset_after_action]} =
               MaybeGenerateTokenChange.change(changeset, options, context)
    end

    test "uses custom argument name when provided" do
      changeset =
        UserWithRememberMe
        |> Ash.Changeset.new()
        |> Ash.Changeset.set_argument(:custom_remember_me, true)

      options = [argument: :custom_remember_me]
      context = %{}

      assert %Ash.Changeset{after_action: [_changeset_after_action]} =
               MaybeGenerateTokenChange.change(changeset, options, context)
    end
  end
end
