# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

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

  alias Example.User

  doctest Password

  describe "reset_token_for/1" do
    test "it generates a token when resets are enabled" do
      user = build_user()
      resettable = %Resettable{password_reset_action_name: :reset, token_lifetime: {72, :hours}}
      strategy = %Password{resettable: resettable, resource: user.__struct__}

      assert {:ok, token} = Password.reset_token_for(strategy, user)
      assert {:ok, claims} = Jwt.peek(token)
      assert claims["act"] == to_string(resettable.password_reset_action_name)
    end
  end

  describe "regressions" do
    test "only one user token is generated for a new user registration" do
      user = build_user()
      subject = AshAuthentication.user_to_subject(user)

      tokens = Example.Token |> Ash.read!(authorize?: false) |> Enum.group_by(& &1.purpose)
      assert [%{subject: ^subject}] = tokens["user"]

      token_types = tokens |> Map.keys() |> MapSet.new()
      assert token_types == MapSet.new(["user", "confirm"])
    end

    test "only one token is generated for a user sign-in" do
      user = build_user()
      subject = AshAuthentication.user_to_subject(user)

      Example.Token |> Ash.bulk_destroy!(:destroy, %{}, authorize?: false)

      strategy = AshAuthentication.Info.strategy!(User, :password)

      {:ok, _signed_in_user} =
        Strategy.action(
          strategy,
          :sign_in,
          %{
            username: user.username,
            password: user.__metadata__.password
          },
          context: [token_type: :sign_in]
        )

      assert [%{subject: ^subject, purpose: "sign_in"}] =
               Example.Token |> Ash.read!(authorize?: false)
    end

    test "sign in tokens can only be used once" do
      user = build_user()
      strategy = AshAuthentication.Info.strategy!(User, :password)

      {:ok, valid_user} =
        Strategy.action(
          strategy,
          :sign_in,
          %{
            username: user.username,
            password: user.__metadata__.password
          },
          context: [token_type: :sign_in]
        )

      assert valid_user.id == user.id
      assert {:ok, %{"purpose" => "sign_in"}} = Jwt.peek(valid_user.__metadata__.token)

      assert {:ok, valid_user2} =
               Strategy.action(
                 strategy,
                 :sign_in_with_token,
                 %{
                   token: valid_user.__metadata__.token
                 }
               )

      assert valid_user.id == valid_user2.id

      assert {:error, _error} =
               Strategy.action(
                 strategy,
                 :sign_in_with_token,
                 %{
                   token: valid_user.__metadata__.token
                 }
               )
    end

    test "users without hashed passwords fail for the right reason" do
      user = build_user()

      user =
        Ash.update!(user, %{hashed_password: nil, confirmed_at: DateTime.utc_now()},
          authorize?: false
        )

      strategy = AshAuthentication.Info.strategy!(User, :password)

      assert {:error, %{caused_by: %{errors: [error]}}} =
               Strategy.action(
                 strategy,
                 :sign_in,
                 %{
                   username: user.username,
                   password: password()
                 }
               )

      assert error.__struct__ == AshAuthentication.Errors.AuthenticationFailed
      assert error.caused_by.module == AshAuthentication.Strategy.Password.SignInPreparation
      assert error.caused_by.message =~ ~r/no users/i
    end
  end
end
