# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.StrategyTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias AshAuthentication.{Info, Strategy, Strategy.OAuth2}

  use Mimic
  import Plug.Test

  describe "Strategy.phases/1" do
    test "it returns the correct phases" do
      phases =
        %OAuth2{}
        |> Strategy.phases()
        |> MapSet.new()

      assert MapSet.equal?(phases, MapSet.new(~w[request callback]a))
    end
  end

  describe "Strategy.actions/1" do
    test "it returns only register when registration is enabled" do
      assert [:register] = Strategy.actions(%OAuth2{})
    end

    test "it returns only sign_in when registration is disabled" do
      assert [:sign_in] = Strategy.actions(%OAuth2{registration_enabled?: false})
    end
  end

  describe "Strategy.method_for_phase/2" do
    test "it is get for the request phase" do
      assert :get = Strategy.method_for_phase(%OAuth2{}, :request)
    end

    test "it is get for the callback phase" do
      assert :get = Strategy.method_for_phase(%OAuth2{}, :callback)
    end
  end

  describe "Strategy.routes/1" do
    test "it returns the correct routes" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)

      routes =
        strategy
        |> Strategy.routes()
        |> MapSet.new()

      assert MapSet.equal?(
               routes,
               MapSet.new([
                 {"/user/oauth2", :request},
                 {"/user/oauth2/callback", :callback}
               ])
             )
    end
  end

  describe "Strategy.plug/3" do
    for phase <- ~w[request callback]a do
      test "it delegates to `OAuth2.Plug.#{phase}/2` for the #{phase} phase" do
        conn = conn(:get, "/")
        strategy = %OAuth2{}

        OAuth2.Plug
        |> expect(unquote(phase), fn rx_conn, rx_strategy ->
          assert rx_conn == conn
          assert rx_strategy == strategy
        end)

        Strategy.plug(strategy, unquote(phase), conn)
      end
    end
  end

  describe "Strategy.action/3" do
    for action <- ~w[register sign_in]a do
      test "it delegates to `OAuth2.Actions.#{action}/2` for the #{action} action" do
        strategy = %OAuth2{}
        params = %{"user_info" => %{}, "oauth_tokens" => %{}}

        OAuth2.Actions
        |> expect(unquote(action), fn rx_strategy, rx_params, _opts ->
          assert rx_strategy == strategy
          assert rx_params == params
        end)

        Strategy.action(strategy, unquote(action), params)
      end
    end
  end
end
