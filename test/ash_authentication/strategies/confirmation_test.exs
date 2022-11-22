defmodule AshAuthentication.Strategy.ConfirmationTest do
  @moduledoc false
  use DataCase, async: true
  alias Ash.Changeset
  alias AshAuthentication.{Info, Jwt, Strategy.Confirmation}
  doctest Confirmation

  describe "confirmation_token/2" do
    test "it generates a confirmation token" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)
      user = build_user()

      new_username = username()
      changeset = Changeset.for_update(user, :update, %{"username" => new_username})

      assert {:ok, token} = Confirmation.confirmation_token(strategy, changeset)
      assert {:ok, claims} = Jwt.peek(token)
      assert claims["act"] == to_string(strategy.confirm_action_name)
      assert claims["chg"] == %{"username" => new_username}
    end
  end
end
