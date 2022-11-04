defmodule AshAuthentication.ConfirmationTest do
  @moduledoc false
  use AshAuthentication.DataCase, async: true
  alias Ash.Changeset
  alias AshAuthentication.Confirmation

  describe "confirmation_token_for/2" do
    test "it returns an error when passed a resource which doesn't support confirmation" do
      token_revocation = build_token_revocation()
      changeset = Changeset.for_update(token_revocation, :update, %{jti: Ecto.UUID.generate()})

      assert {:error, reason} = Confirmation.confirmation_token_for(changeset, token_revocation)
      assert reason =~ ~r/confirmation not supported/i
    end

    test "it returns a confirmation token" do
      user = build_user()
      changeset = Changeset.for_update(user, :update, %{username: username()})

      assert {:ok, token} = Confirmation.confirmation_token_for(changeset, user)
      assert token =~ ~r/^[\w\._-]+$/
    end
  end

  describe "confirm/2" do
    test "creates can be confirmed" do
      user = build_user()

      refute user.confirmed_at

      token = user.__metadata__.confirmation_token

      assert token =~ ~r/^[\w\._-]+$/

      assert {:ok, updated_user} =
               Confirmation.confirm(Example.UserWithUsername, %{"confirm" => token})

      assert updated_user.id == user.id

      assert_in_delta(
        DateTime.to_unix(updated_user.confirmed_at),
        DateTime.to_unix(DateTime.utc_now()),
        1.0
      )
    end
  end
end
