defmodule AshAuthentication.Strategy.MagicLinkTest do
  @moduledoc false
  use DataCase, async: true

  import ExUnit.CaptureLog
  import Plug.Test
  alias AshAuthentication.{Info, Jwt, Plug, Strategy, Strategy.MagicLink}

  doctest MagicLink

  describe "request_token_for/2" do
    test "it generates a sign in token" do
      user = build_user()
      strategy = Info.strategy!(Example.User, :magic_link)

      assert {:ok, token} = MagicLink.request_token_for(strategy, user)

      assert {:ok, claims} = Jwt.peek(token)
      assert claims["act"] == to_string(strategy.sign_in_action_name)
    end
  end

  describe "actions" do
    test "with registration enabld" do
      strategy =
        Info.strategy!(Example.UserWithRegisterMagicLink, :magic_link)

      log =
        capture_log(fn ->
          MagicLink.Actions.request(
            strategy,
            %{"email" => "hello@example.com"},
            []
          )
        end)

      token =
        log
        |> String.split("Magic link request for hello@example.com, token \"", parts: 2)
        |> Enum.at(1)
        |> String.split("\"", parts: 2)
        |> Enum.at(0)

      assert {:ok,
              %Example.UserWithRegisterMagicLink{
                email: %Ash.CiString{string: "hello@example.com"}
              }} =
               MagicLink.Actions.sign_in(strategy, %{"token" => token}, [])
    end
  end
end
