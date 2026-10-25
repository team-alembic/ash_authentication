# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOns.LogOutEverywhereTest do
  @moduledoc false
  use DataCase, async: false
  alias AshAuthentication.{Info, Jwt, Strategy, Strategy.Password, TokenResource}

  describe "log_out_everywhere action" do
    test "all existing tokens for a user a revoked" do
      user = build_user_with_token_required()
      strategy = Info.strategy!(Example.UserWithTokenRequired, :log_out_everywhere)
      jtis = issue_tokens(user, 3)

      assert :ok = Strategy.action(strategy, :log_out_everywhere, %{user: user})

      for jti <- jtis do
        assert TokenResource.jti_revoked?(Example.Token, jti)
      end
    end

    test "a password reset succeeds and revokes the user's existing tokens" do
      user = build_user_with_token_required()
      strategy = Info.strategy!(Example.UserWithTokenRequired, :password)
      jtis = issue_tokens(user, 3)

      {:ok, reset_token} = Password.reset_token_for(strategy, user)

      assert {:ok, _user} =
               Strategy.action(strategy, :reset, %{
                 "reset_token" => reset_token,
                 "password" => "barfoobaz",
                 "password_confirmation" => "barfoobaz"
               })

      for jti <- jtis do
        assert TokenResource.jti_revoked?(Example.Token, jti)
      end

      assert TokenResource.token_revoked?(Example.Token, reset_token)
    end

    for action <- [:change_password_atomic, :change_password_nonatomic] do
      test "a password change by #{action} revokes the user's existing tokens" do
        user = build_user_with_token_required()
        jtis = issue_tokens(user, 3)

        user
        |> Ash.Changeset.for_update(unquote(action), %{password: "barfoobaz"})
        |> Ash.update!()

        for jti <- jtis do
          assert TokenResource.jti_revoked?(Example.Token, jti)
        end
      end
    end
  end

  defp issue_tokens(user, count) do
    for _ <- 1..count do
      {:ok, _token, %{"jti" => jti}} = Jwt.token_for_user(user)
      jti
    end
  end

  test "log_out_everywhere revokes remember_me tokens" do
    user = build_user_with_remember_me()
    {:ok, remember_me_token} = generate_remember_me_token(user)

    {:ok, _session_token, %{"jti" => session_jti}} = Jwt.token_for_user(user)

    refute TokenResource.token_revoked?(Example.Token, remember_me_token)
    refute TokenResource.jti_revoked?(Example.Token, session_jti)

    strategy = Info.strategy!(Example.UserWithRememberMe, :log_out_everywhere)

    assert :ok = Strategy.action(strategy, :log_out_everywhere, %{user: user})
    assert TokenResource.token_revoked?(Example.Token, remember_me_token)
    assert TokenResource.jti_revoked?(Example.Token, session_jti)
  end

  test "atomic updates to non-`hashed_password` fields do not trigger the log_out_everywhere functionality" do
    user =
      Example.UserWithTokenRequired
      |> Ash.Changeset.for_create(:register_with_password, %{
        email: "test",
        password: "password",
        password_confirmation: "password"
      })
      |> Ash.create!()

    # Base token is okay
    assert {:ok, _data, Example.UserWithTokenRequired} =
             AshAuthentication.Jwt.verify(user.__metadata__.token, :ash_authentication)

    # Non-atomic update is okay
    user =
      user
      |> Ash.Changeset.for_update(:update_email_nonatomic, %{email: "foo"})
      |> Ash.update!()

    assert {:ok, _data, Example.UserWithTokenRequired} =
             AshAuthentication.Jwt.verify(user.__metadata__.token, :ash_authentication)

    # Atomic update *should* be okay - but is not
    user =
      user
      |> Ash.Changeset.for_update(:update_email_atomic, %{email: "foo2"})
      |> Ash.update!()

    assert {:ok, _data, Example.UserWithTokenRequired} =
             AshAuthentication.Jwt.verify(user.__metadata__.token, :ash_authentication)
  end
end
