# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.RememberMe.StrategyTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias AshAuthentication.{
    Strategy,
    Strategy.RememberMe
  }

  import Plug.Test

  describe "Strategy.phases/1" do
    test "it returns an empty list" do
      strategy = %RememberMe{}
      assert Strategy.phases(strategy) == []
    end
  end

  describe "Strategy.actions/1" do
    test "it returns an empty list" do
      strategy = %RememberMe{}
      assert Strategy.actions(strategy) == []
    end
  end

  describe "Strategy.routes/1" do
    test "it returns an empty list" do
      strategy = %RememberMe{}
      assert Strategy.routes(strategy) == []
    end
  end

  describe "Strategy.plug/3" do
    test "it returns the conn unchanged" do
      conn = conn(:get, "/")
      strategy = %RememberMe{}
      assert Strategy.plug(strategy, :any_phase, conn) == conn
    end
  end

  describe "Strategy.action/3" do
    test "it returns :ok" do
      strategy = %RememberMe{}
      assert Strategy.action(strategy, :any_action, %{}, []) == :ok
    end
  end

  describe "Strategy.tokens_required?/1" do
    test "it always returns true" do
      strategy = %RememberMe{}
      assert Strategy.tokens_required?(strategy) == true
    end
  end

  describe "Strategy.name/1" do
    test "it returns the strategy name" do
      strategy = %RememberMe{name: :my_remember_me}
      assert Strategy.name(strategy) == :my_remember_me
    end
  end

  describe "Strategy.method_for_phase/2" do
    test "it always returns :post" do
      strategy = %RememberMe{}
      assert Strategy.method_for_phase(strategy, :any_phase) == :post
    end
  end
end
