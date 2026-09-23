# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOns.LogOutEverywhereTest do
  @moduledoc false
  use DataCase, async: false
  alias AshAuthentication.{Info, Jwt, Strategy, TokenResource}
  alias AshAuthentication.Plug.Helpers

  describe "log_out_everywhere action" do
    test "notifies every revocation and rejects revoked sessions without affecting another user" do
      user = build_user_with_token_required()
      user_id = user.id
      other = build_user_with_token_required()
      other_id = other.id
      {:ok, other_token, %{"jti" => other_jti}} = Jwt.token_for_user(other)
      strategy = Info.strategy!(Example.UserWithTokenRequired, :log_out_everywhere)

      sessions =
        for _index <- 1..3 do
          {:ok, token, %{"jti" => jti}} = Jwt.token_for_user(user)
          session = %{"user_with_token_required_token" => token}
          assert {:ok, %{id: ^user_id}} = authenticate_session(session)
          {jti, session}
        end

      other_session = %{"user_with_token_required_token" => other_token}
      assert {:ok, %{id: ^other_id}} = authenticate_session(other_session)

      assert :ok = Strategy.action(strategy, :log_out_everywhere, %{user: user}, actor: self())

      for {jti, session} <- sessions do
        assert_receive {:token_notification, %{data: %{jti: ^jti, purpose: "revocation"}}}
        assert TokenResource.jti_revoked?(Example.Token, jti)
        assert :error = authenticate_session(session)
      end

      refute TokenResource.jti_revoked?(Example.Token, other_jti)
      refute_received {:token_notification, %{data: %{jti: ^other_jti}}}
      assert {:ok, %{id: ^other_id}} = authenticate_session(other_session)
    end

    test "all existing tokens for a user a revoked" do
      user = build_user_with_token_required()
      strategy = Info.strategy!(Example.UserWithTokenRequired, :log_out_everywhere)

      jtis =
        [0..3]
        |> Enum.map(fn _ ->
          {:ok, _token, %{"jti" => jti}} = Jwt.token_for_user(user)
          jti
        end)

      assert :ok = Strategy.action(strategy, :log_out_everywhere, %{user: user}, [])

      for jti <- jtis do
        assert TokenResource.jti_revoked?(Example.UserWithTokenRequired, jti)
      end
    end

    test "all existing tokens for a user a revoked on password reset" do
      user =
        build_user_with_token_required(
          password: "foobarbaz",
          password_confirmation: "foobarbaz"
        )

      strategy =
        Info.strategy!(Example.UserWithTokenRequired, :password)

      jtis =
        [0..3]
        |> Enum.map(fn _ ->
          {:ok, _token, %{"jti" => jti}} = Jwt.token_for_user(user)
          jti
        end)

      Strategy.action(
        strategy,
        :reset,
        %{
          current_password: "foobarbaz",
          password: "barfoobaz",
          password_confirmation: "barfoobaz"
        },
        []
      )

      for jti <- jtis do
        assert TokenResource.jti_revoked?(Example.UserWithTokenRequired, jti)
      end
    end
  end

  defp authenticate_session(session) do
    Helpers.authenticate_resource_from_session(
      Example.UserWithTokenRequired,
      session,
      :ash_authentication,
      []
    )
  end

  test "log_out_everywhere revokes remember_me tokens" do
    user = build_user_with_remember_me()
    {:ok, remember_me_token} = generate_remember_me_token(user)

    {:ok, _session_token, %{"jti" => session_jti}} = Jwt.token_for_user(user)

    refute TokenResource.token_revoked?(Example.Token, remember_me_token)
    refute TokenResource.jti_revoked?(Example.Token, session_jti)

    strategy = Info.strategy!(Example.UserWithRememberMe, :log_out_everywhere)

    assert :ok = Strategy.action(strategy, :log_out_everywhere, %{user: user}, [])
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
