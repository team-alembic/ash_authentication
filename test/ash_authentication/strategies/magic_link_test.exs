defmodule AshAuthentication.Strategy.MagicLinkTest do
  @moduledoc false
  use DataCase, async: true

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
end
