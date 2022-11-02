defmodule AshAuthentication.PasswordResetTest do
  @moduledoc false
  use AshAuthentication.DataCase, async: true
  alias AshAuthentication.PasswordReset
  import ExUnit.CaptureLog

  describe "enabled?/1" do
    test "is false when the resource doesn't support password resets" do
      refute PasswordReset.enabled?(Example.TokenRevocation)
    end

    test "it is true when the resource does support password resets" do
      assert PasswordReset.enabled?(Example.UserWithUsername)
    end
  end

  describe "reset_password_request/1" do
    test "it generates a password reset token" do
      {:ok, user} =
        build_user()
        |> PasswordReset.request_password_reset()

      assert user.__metadata__.reset_token =~ ~r/[\w.]/i
    end

    test "it sends the reset instructions" do
      assert capture_log(fn ->
               {:ok, _} =
                 build_user()
                 |> PasswordReset.request_password_reset()
             end) =~ ~r/Password reset request/i
    end
  end

  describe "reset_password/2" do
    test "when the reset token is valid, it can change the password" do
      {:ok, user} =
        build_user()
        |> PasswordReset.request_password_reset()

      password = password()

      attrs = %{
        "reset_token" => user.__metadata__.reset_token,
        "password" => password,
        "password_confirmation" => password
      }

      {:ok, new_user} = PasswordReset.reset_password(Example.UserWithUsername, attrs)

      assert new_user.hashed_password != user.hashed_password
    end

    test "when the reset token is invalid, it doesn't change the password" do
      user = build_user()

      password = password()

      attrs = %{
        "reset_token" => Ecto.UUID.generate(),
        "password" => password,
        "password_confirmation" => password
      }

      assert {:error, _} = PasswordReset.reset_password(Example.UserWithUsername, attrs)

      {:ok, reloaded_user} = Example.get(Example.UserWithUsername, id: user.id)
      assert reloaded_user.hashed_password == user.hashed_password
    end
  end
end
