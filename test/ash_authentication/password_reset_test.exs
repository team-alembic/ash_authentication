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
    test "when the user is found, it returns an empty list" do
      user = build_user()

      assert {:ok, []} =
               PasswordReset.request_password_reset(Example.UserWithUsername, %{
                 "username" => user.username
               })
    end

    test "when the user is not found, it returns an empty list" do
      assert {:ok, []} =
               PasswordReset.request_password_reset(Example.UserWithUsername, %{
                 "username" => username()
               })
    end

    test "when the user is found it sends the reset instructions" do
      user = build_user()

      log =
        capture_log(fn ->
          PasswordReset.request_password_reset(Example.UserWithUsername, %{
            "username" => user.username
          })
        end)

      assert log =~ ~r/Password reset request/i
    end

    test "when the user is not found, it doesn't send reset instructions" do
      refute capture_log(fn ->
               PasswordReset.request_password_reset(Example.UserWithUsername, %{
                 "username" => username()
               })
             end) =~ ~r/Password reset request/i
    end
  end

  describe "reset_password/2" do
    test "when the reset token is valid, it can change the password" do
      user = build_user()
      {:ok, token} = PasswordReset.reset_token_for(user)
      password = password()

      attrs = %{
        "reset_token" => token,
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

  describe "reset_token_for/1" do
    test "when given a resource which supports password resets, it generates a token" do
      assert {:ok, token} =
               build_user()
               |> PasswordReset.reset_token_for()

      assert token =~ ~r/^[\w\.-]+$/
    end

    test "when given a resource which doesn't support password resets, it returns an error" do
      assert :error =
               build_token_revocation()
               |> PasswordReset.reset_token_for()
    end
  end
end
