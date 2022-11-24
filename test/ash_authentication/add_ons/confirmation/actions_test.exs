defmodule AshAuthentication.AddOn.Confirmation.ActionsTest do
  @moduledoc false
  use DataCase, async: true

  alias Ash.Changeset
  alias AshAuthentication.{AddOn.Confirmation, AddOn.Confirmation.Actions, Info}

  describe "confirm/2" do
    test "it returns an error when there is no corresponding user" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)
      user = build_user()

      changeset =
        user
        |> Changeset.for_update(:update, %{"username" => username()})

      {:ok, token} = Confirmation.confirmation_token(strategy, changeset)

      Example.Repo.delete!(user)

      assert {:error, error} = Actions.confirm(strategy, %{"confirm" => token})
      assert Exception.message(error) == "record not found"
    end

    test "it returns an error when the token is invalid" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)

      assert {:error, error} = Actions.confirm(strategy, %{"confirm" => Ecto.UUID.generate()})
      assert Exception.message(error) == "Invalid confirmation token"
    end

    test "it updates the confirmed_at field" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)
      user = build_user()
      new_username = username()

      changeset =
        user
        |> Changeset.for_update(:update, %{"username" => new_username})

      {:ok, token} = Confirmation.confirmation_token(strategy, changeset)

      assert {:ok, confirmed_user} = Actions.confirm(strategy, %{"confirm" => token})

      assert confirmed_user.id == user.id
      assert to_string(confirmed_user.username) == new_username

      assert_in_delta DateTime.to_unix(confirmed_user.confirmed_at),
                      DateTime.to_unix(DateTime.utc_now()),
                      1.0
    end
  end
end
