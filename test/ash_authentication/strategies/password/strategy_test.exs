defmodule AshAuthentication.Strategy.Password.StrategyTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias AshAuthentication.{
    Info,
    Strategy,
    Strategy.Password,
    Strategy.Password.Resettable
  }

  use Mimic
  import Plug.Test

  describe "Strategy.phases/1" do
    test "it returns the correct phases when the strategy supports resetting" do
      strategy = %Password{resettable: %Resettable{}}

      phases =
        strategy
        |> Strategy.phases()
        |> MapSet.new()

      assert MapSet.equal?(phases, MapSet.new(~w[register sign_in reset_request reset]a))
    end

    test "it returns the correct phases when the strategy doesn't support resetting" do
      strategy = %Password{}

      phases =
        strategy
        |> Strategy.phases()
        |> MapSet.new()

      assert MapSet.equal?(phases, MapSet.new(~w[register sign_in]a))
    end
  end

  describe "Strategy.actions/1" do
    test "it returns the correct actions when the strategy supports resetting" do
      strategy = %Password{resettable: %Resettable{}}

      actions =
        strategy
        |> Strategy.actions()
        |> MapSet.new()

      assert MapSet.equal?(actions, MapSet.new(~w[register sign_in reset_request reset]a))
    end

    test "it returns the correct actions when the strategy doesn't support resetting" do
      strategy = %Password{}

      actions =
        strategy
        |> Strategy.actions()
        |> MapSet.new()

      assert MapSet.equal?(actions, MapSet.new(~w[register sign_in]a))
    end
  end

  describe "Strategy.method_for_phase/2" do
    for phase <- ~w[register sign_in reset_request reset]a do
      test "it is post for the #{phase} phase" do
        assert :post ==
                 %Password{}
                 |> Strategy.method_for_phase(unquote(phase))
      end
    end
  end

  describe "Strategy.routes/1" do
    test "it returns the correct routes when the strategy supports resetting" do
      {:ok, strategy} = Info.strategy(Example.User, :password)

      routes =
        strategy
        |> Strategy.routes()
        |> MapSet.new()

      assert MapSet.equal?(
               routes,
               MapSet.new([
                 {"/user/password/register", :register},
                 {"/user/password/reset", :reset},
                 {"/user/password/reset_request", :reset_request},
                 {"/user/password/sign_in", :sign_in},
                 {"/user/password/sign_in_with_token", :sign_in_with_token}
               ])
             )
    end

    test "it returns the correct routes when the strategy isn't resettable" do
      {:ok, strategy} = Info.strategy(Example.User, :password)

      routes =
        %{strategy | resettable: nil}
        |> Strategy.routes()
        |> MapSet.new()

      assert MapSet.equal?(
               routes,
               MapSet.new([
                 {"/user/password/register", :register},
                 {"/user/password/sign_in", :sign_in},
                 {"/user/password/sign_in_with_token", :sign_in_with_token}
               ])
             )
    end
  end

  describe "Strategy.plug/3" do
    for phase <- ~w[register sign_in reset_request reset]a do
      test "it delegates to `Password.Plug.#{phase}/2` for the #{phase} phase" do
        conn = conn(:get, "/")
        strategy = %Password{}

        Password.Plug
        |> expect(unquote(phase), fn rx_conn, rx_strategy ->
          assert rx_conn == conn
          assert rx_strategy == strategy
        end)

        Strategy.plug(strategy, unquote(phase), conn)
      end
    end
  end

  describe "Strategy.action/3" do
    for action <- ~w[register sign_in reset_request reset]a do
      test "it delegates to `Password.Actions.#{action}/2` for the #{action} action" do
        strategy = %Password{}
        params = %{"username" => Faker.Internet.user_name()}

        Password.Actions
        |> expect(unquote(action), fn rx_strategy, rx_params, _opts ->
          assert rx_strategy == strategy
          assert rx_params == params
        end)

        Strategy.action(strategy, unquote(action), params)
      end
    end
  end
end
