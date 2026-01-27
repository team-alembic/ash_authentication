# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.SenderTest do
  @moduledoc false
  use DataCase, async: false

  alias AshAuthentication.{Errors.SenderFailed, Info, Strategy}
  alias AshAuthentication.Strategy.{MagicLink, Password}

  setup do
    Example.FailingSender.clear_failure()
    on_exit(fn -> Example.FailingSender.clear_failure() end)
    :ok
  end

  describe "password reset sender failure" do
    test "propagates sender errors through the generic action" do
      user = build_user_with_failing_sender()
      strategy = Info.strategy!(Example.UserWithFailingSender, :password)

      Example.FailingSender.set_failure(:email_delivery_failed)

      assert {:error, error} =
               Password.Actions.reset_request(
                 strategy,
                 %{"email" => to_string(user.email)},
                 []
               )

      assert %SenderFailed{reason: :email_delivery_failed} = unwrap_error(error)
    end

    test "succeeds when sender returns :ok" do
      user = build_user_with_failing_sender()
      strategy = Info.strategy!(Example.UserWithFailingSender, :password)

      assert :ok =
               Password.Actions.reset_request(
                 strategy,
                 %{"email" => to_string(user.email)},
                 []
               )
    end
  end

  describe "magic link sender failure" do
    test "propagates sender errors for existing user" do
      user = build_user_with_failing_sender()
      strategy = Info.strategy!(Example.UserWithFailingSender, :magic_link)

      Example.FailingSender.set_failure(:sms_gateway_unavailable)

      assert {:error, error} =
               MagicLink.Actions.request(
                 strategy,
                 %{"email" => to_string(user.email)},
                 []
               )

      assert %SenderFailed{reason: :sms_gateway_unavailable} = unwrap_error(error)
    end

    test "propagates sender errors for new user registration" do
      strategy = Info.strategy!(Example.UserWithFailingSender, :magic_link)

      Example.FailingSender.set_failure(:rate_limited)

      assert {:error, error} =
               MagicLink.Actions.request(
                 strategy,
                 %{"email" => "new_user_#{System.unique_integer([:positive])}@example.com"},
                 []
               )

      assert %SenderFailed{reason: :rate_limited} = unwrap_error(error)
    end

    test "succeeds when sender returns :ok" do
      user = build_user_with_failing_sender()
      strategy = Info.strategy!(Example.UserWithFailingSender, :magic_link)

      assert :ok =
               MagicLink.Actions.request(
                 strategy,
                 %{"email" => to_string(user.email)},
                 []
               )
    end
  end

  describe "confirmation sender failure" do
    test "propagates sender errors during user registration" do
      strategy = Info.strategy!(Example.UserWithFailingSender, :password)

      Example.FailingSender.set_failure(:confirmation_email_blocked)

      assert {:error, error} =
               Strategy.action(
                 strategy,
                 :register,
                 %{
                   "email" => "new_user_#{System.unique_integer([:positive])}@example.com",
                   "password" => password(),
                   "password_confirmation" => password()
                 }
               )

      assert %SenderFailed{reason: :confirmation_email_blocked} = unwrap_error(error)
    end

    test "succeeds when sender returns :ok during registration" do
      strategy = Info.strategy!(Example.UserWithFailingSender, :password)

      assert {:ok, user} =
               Strategy.action(
                 strategy,
                 :register,
                 %{
                   "email" => "new_user_#{System.unique_integer([:positive])}@example.com",
                   "password" => password(),
                   "password_confirmation" => password()
                 }
               )

      assert user.email
    end
  end

  describe "SenderFunction error propagation" do
    test "returns errors from function-based senders" do
      sender = AshAuthentication.SenderFunction

      assert {:error, :function_failed} =
               sender.send(%{}, "token", fun: fn _user, _token -> {:error, :function_failed} end)
    end

    test "returns :ok from successful function-based senders" do
      sender = AshAuthentication.SenderFunction

      assert :ok = sender.send(%{}, "token", fun: fn _user, _token -> :ok end)
    end

    test "treats other return values as :ok for backwards compatibility" do
      sender = AshAuthentication.SenderFunction

      assert :ok = sender.send(%{}, "token", fun: fn _user, _token -> {:ok, "sent"} end)
    end
  end

  defp build_user_with_failing_sender(attrs \\ []) do
    password = password()

    attrs =
      attrs
      |> Map.new()
      |> Map.put_new(:email, "user_#{System.unique_integer([:positive])}@example.com")
      |> Map.put_new(:password, password)
      |> Map.put_new(:password_confirmation, password)

    Example.UserWithFailingSender
    |> Ash.Changeset.new()
    |> Ash.Changeset.for_create(:register_with_password, attrs)
    |> Ash.Changeset.force_change_attribute(:confirmed_at, DateTime.utc_now())
    |> Ash.create!()
  end

  defp unwrap_error(%Ash.Error.Invalid{errors: [error | _]}), do: unwrap_error(error)
  defp unwrap_error(%Ash.Error.Forbidden{errors: [error | _]}), do: unwrap_error(error)

  defp unwrap_error(%AshAuthentication.Errors.AuthenticationFailed{caused_by: caused_by}),
    do: unwrap_error(caused_by)

  defp unwrap_error(error), do: error
end
