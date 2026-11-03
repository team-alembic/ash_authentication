# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Password.SignInWithoutTokensTest do
  @moduledoc false
  use DataCase

  alias AshAuthentication.{Errors.AuthenticationFailed, Info, Strategy, Strategy.Password.Actions}

  test "signs in with authentication tokens disabled without minting JWT metadata" do
    assert Info.authentication_tokens_enabled?(Example.UserWithTokensDisabled) == false

    user = build_user_with_tokens_disabled()
    {:ok, strategy} = Info.strategy(Example.UserWithTokensDisabled, :password)
    assert strategy.sign_in_tokens_enabled? == false

    assert {:ok, signed_in} =
             Actions.sign_in(
               strategy,
               %{
                 "email" => user.email,
                 "password" => user.__metadata__.password
               },
               []
             )

    refute Map.has_key?(signed_in.__metadata__ || %{}, :token)
    assert signed_in.__metadata__[:authentication_strategies] == [:password]
  end

  test "returns an authentication error when the password is wrong" do
    user = build_user_with_tokens_disabled()
    {:ok, strategy} = Info.strategy(Example.UserWithTokensDisabled, :password)

    assert {:error, %AuthenticationFailed{}} =
             Actions.sign_in(
               strategy,
               %{"email" => user.email, "password" => "wrong password"},
               []
             )
  end

  test "Strategy.action/4 succeeds when authentication tokens are disabled" do
    user = build_user_with_tokens_disabled()
    strategy = Info.strategy!(Example.UserWithTokensDisabled, :password)

    assert {:ok, signed_in} =
             Strategy.action(
               strategy,
               :sign_in,
               %{
                 email: user.email,
                 password: user.__metadata__.password
               },
               []
             )

    refute Map.has_key?(signed_in.__metadata__ || %{}, :token)
  end
end
