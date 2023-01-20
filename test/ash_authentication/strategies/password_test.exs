defmodule AshAuthentication.Strategy.PasswordTest do
  @moduledoc false
  use DataCase, async: true

  import Plug.Test

  alias AshAuthentication.{
    Info,
    Jwt,
    Plug,
    Strategy,
    Strategy.Password,
    Strategy.Password.Resettable
  }

  doctest Password

  describe "reset_token_for/1" do
    test "it generates a token when resets are enabled" do
      user = build_user()
      resettable = %Resettable{password_reset_action_name: :reset, token_lifetime: 72}
      strategy = %Password{resettable: [resettable], resource: user.__struct__}

      assert {:ok, token} = Password.reset_token_for(strategy, user)

      assert {:ok, claims} = Jwt.peek(token)
      assert claims["act"] == to_string(resettable.password_reset_action_name)
    end
  end
end
