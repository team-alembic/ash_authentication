defmodule AshAuthentication.AddOn.Confirmation.ConfirmationHookChangeTest do
  @moduledoc false
  use DataCase, async: false
  import ExUnit.CaptureLog

  describe "when creating a new user" do
    test "it always sends a confirmation" do
      username = username()

      assert capture_log(fn -> build_user(username: username) end) =~
               ~r/Confirmation request for user #{username}/
    end
  end

  describe "when updating an existing user" do
    test "it sends a confirmation for the new username" do
      user = build_user()
      new_username = username()

      assert capture_log(fn -> Example.User.update_user!(user, %{username: new_username}) end) =~
               ~r/Confirmation request for user #{new_username}/
    end

    test "it creates an error " do
      user = build_user()
      new_username = username()
      build_user(username: new_username)

      assert_raise Ash.Error.Invalid, ~r/username: has already been taken/, fn ->
        Example.User.update_user!(user, %{username: new_username})
      end
    end
  end
end
