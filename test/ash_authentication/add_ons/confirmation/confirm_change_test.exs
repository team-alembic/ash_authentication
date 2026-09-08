# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AddOn.Confirmation.ConfirmChangeTest do
  @moduledoc false
  use DataCase, async: true

  alias Ash.Changeset
  alias Ash.Error.Changes.InvalidArgument

  alias AshAuthentication.{
    AddOn.Confirmation,
    Errors.InvalidToken,
    Info,
    Strategy.OAuth2.UserResolver
  }

  describe "the generated confirm action" do
    test "it refuses a token which was issued for another record" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)

      attacker = build_user()
      victim = build_user()
      victim_username = to_string(victim.username)

      attacker_new_username = username()

      {:ok, token} =
        Confirmation.confirmation_token(
          strategy,
          Changeset.for_update(attacker, :update, %{"username" => attacker_new_username}),
          attacker
        )

      assert {:error, error} =
               victim
               |> Changeset.for_update(strategy.confirm_action_name, %{"confirm" => token})
               |> Ash.update()

      assert [%InvalidArgument{field: :confirm}] = error.errors

      reloaded = Ash.get!(Example.User, victim.id)
      assert to_string(reloaded.username) == victim_username
      assert is_nil(reloaded.confirmed_at)
    end

    test "it refuses a token which has already been used" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)

      user = build_user()
      new_username = username()

      {:ok, token} =
        Confirmation.confirmation_token(
          strategy,
          Changeset.for_update(user, :update, %{"username" => new_username}),
          user
        )

      assert {:ok, confirmed} =
               user
               |> Changeset.for_update(strategy.confirm_action_name, %{"confirm" => token})
               |> Ash.update()

      assert to_string(confirmed.username) == new_username

      assert {:error, error} =
               confirmed
               |> Changeset.for_update(strategy.confirm_action_name, %{"confirm" => token})
               |> Ash.update()

      assert [%InvalidArgument{field: :confirm}] = error.errors
    end
  end

  describe "Confirmation.Actions.confirm/3" do
    test "it applies the stored changes and revokes the token" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)

      user = build_user()
      new_username = username()

      {:ok, token} =
        Confirmation.confirmation_token(
          strategy,
          Changeset.for_update(user, :update, %{"username" => new_username}),
          user
        )

      assert {:ok, confirmed} = Confirmation.Actions.confirm(strategy, %{"confirm" => token})
      assert confirmed.id == user.id
      assert to_string(confirmed.username) == new_username
      refute is_nil(confirmed.confirmed_at)

      assert {:error, %InvalidToken{}} =
               Confirmation.Actions.confirm(strategy, %{"confirm" => token})
    end

    test "it links a pending provider identity and revokes the token" do
      {:ok, strategy} = Info.strategy(Example.User, :confirm)
      {:ok, oauth_strategy} = Info.strategy(Example.User, :oauth2_confirm_link)

      user = build_user()
      uid = "user:#{Ecto.UUID.generate()}"

      payload = %{
        "strategy" => "oauth2_confirm_link",
        "user_info" => %{"sub" => uid},
        "oauth_tokens" => %{"access_token" => Ecto.UUID.generate()}
      }

      {:ok, token} = Confirmation.confirmation_token_for_link(strategy, user, payload, [])

      assert :error = UserResolver.fetch_identity(oauth_strategy, uid)

      assert {:ok, confirmed} = Confirmation.Actions.confirm(strategy, %{"confirm" => token})
      refute is_nil(confirmed.confirmed_at)

      assert {:ok, identity} = UserResolver.fetch_identity(oauth_strategy, uid)
      assert identity.user_id == user.id

      assert {:error, %InvalidToken{}} =
               Confirmation.Actions.confirm(strategy, %{"confirm" => token})
    end
  end
end
