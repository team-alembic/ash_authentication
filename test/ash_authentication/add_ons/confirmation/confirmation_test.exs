defmodule AshAuthentication.AddOn.ConfirmationTest do
  @moduledoc false
  use DataCase, async: true
  import Plug.Test
  alias Ash.Changeset
  alias AshAuthentication.{AddOn.Confirmation, Info, Jwt, Plug, Strategy}

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
    end

    test "it stores changes in the token resource" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)
      user = build_user()

      new_username = username()
      changeset = Changeset.for_update(user, :update, %{"username" => new_username})

      assert {:ok, token} = Confirmation.confirmation_token(strategy, changeset)
      assert {:ok, claims} = Jwt.peek(token)
      assert {:ok, changes} = Confirmation.Actions.get_changes(strategy, claims["jti"])

      assert [{"username", new_username}] == Enum.to_list(changes)
    end

    test "it does not store the changes in the confirmation token" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)
      user = build_user()

      new_username = username()
      changeset = Changeset.for_update(user, :update, %{"username" => new_username})

      assert {:ok, token} = Confirmation.confirmation_token(strategy, changeset)
      assert {:ok, claims} = Jwt.peek(token)

      refute Map.has_key?(claims, "chg")
    end
  end

  def confirmation_token do
    {:ok, strategy} = Info.strategy(Example.User, :confirm)
    user = build_user()

    new_username = username()
    changeset = Changeset.for_update(user, :update, %{"username" => new_username})

    assert {:ok, token} = Confirmation.confirmation_token(strategy, changeset)
    token
  end

  def one_second_ago do
    DateTime.utc_now()
    |> DateTime.add(-1, :second)
    |> DateTime.to_unix()
  end
end
