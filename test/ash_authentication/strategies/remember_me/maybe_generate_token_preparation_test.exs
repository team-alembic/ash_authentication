defmodule AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenPreparationTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenPreparation
  alias Example.UserWithRememberMe

  describe "prepare/3" do
    test "returns query unchanged when remember_me argument is false" do
      query =
        UserWithRememberMe
        |> Ash.Query.new()
        |> Ash.Query.set_argument(:remember_me, false)

      options = []
      context = %{}

      result = MaybeGenerateTokenPreparation.prepare(query, options, context)
      assert result == query
    end

    test "returns query unchanged when remember_me argument is nil" do
      query =
        UserWithRememberMe
        |> Ash.Query.new()
        |> Ash.Query.set_argument(:remember_me, nil)

      options = []
      context = %{}

      result = MaybeGenerateTokenPreparation.prepare(query, options, context)
      assert result == query
    end

    test "calls prepare_after_action when remember_me argument is true" do
      query =
        UserWithRememberMe
        |> Ash.Query.new()
        |> Ash.Query.set_argument(:remember_me, true)

      options = []
      context = %{}

      assert %Ash.Query{after_action: [_prepare_after_action]} =
               MaybeGenerateTokenPreparation.prepare(query, options, context)
    end

    test "uses custom argument name when provided" do
      query =
        UserWithRememberMe
        |> Ash.Query.new()
        |> Ash.Query.set_argument(:custom_remember_me, true)

      options = [argument: :custom_remember_me]
      context = %{}

      assert %Ash.Query{after_action: [_prepare_after_action]} =
               MaybeGenerateTokenPreparation.prepare(query, options, context)
    end
  end
end
