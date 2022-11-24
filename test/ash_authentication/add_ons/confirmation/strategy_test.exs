defmodule AshAuthentication.AddOn.Confirmation.StrategyTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias AshAuthentication.{AddOn.Confirmation, Info, Strategy}

  use Mimic
  import Plug.Test

  describe "Strategy.phases/1" do
    test "it returns the correct phase" do
      assert [:confirm] = Strategy.phases(%Confirmation{})
    end
  end

  describe "Strategy.actions/1" do
    test "it returns the correct action" do
      assert [:confirm] = Strategy.actions(%Confirmation{})
    end
  end

  describe "Strategy.routes/1" do
    test "it returns the correct route" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)

      assert [{"/user/confirm", :confirm}] = Strategy.routes(strategy)
    end
  end

  describe "Strategy.plug/3" do
    test "it delegates to `Confirmation.Plug.confirm/2` for the confirm phase" do
      conn = conn(:get, "/")
      strategy = %Confirmation{}

      Confirmation.Plug
      |> expect(:confirm, fn rx_conn, rx_strategy ->
        assert rx_conn == conn
        assert rx_strategy == strategy
      end)

      Strategy.plug(strategy, :confirm, conn)
    end
  end

  describe "Strategy.action/3" do
    test "it delegates to `Confirmation.Actions.confirm/2` for the confirm action" do
      strategy = %Confirmation{}
      params = %{"confirm" => Ecto.UUID.generate()}

      Confirmation.Actions
      |> expect(:confirm, fn rx_strategy, rx_params ->
        assert rx_strategy == strategy
        assert rx_params == params
      end)

      Strategy.action(strategy, :confirm, params)
    end
  end
end
