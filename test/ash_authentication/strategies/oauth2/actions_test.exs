# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.ActionsTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.{
    AddOn.Confirmation,
    Errors.AuthenticationFailed,
    Errors.ConfirmationRequired,
    Errors.InvalidToken,
    Info,
    Jwt,
    Strategy.OAuth2.Actions,
    Strategy.OAuth2.UserResolver,
    UserIdentity
  }

  require Ash.Query

  defp confirmation_add_on do
    Enum.find(
      AshAuthentication.Info.authentication_add_ons(Example.User),
      &match?(%Confirmation{}, &1)
    )
  end

  defp seed_identity(strategy_name, user, sub) do
    {:ok, _identity} =
      UserIdentity.Actions.upsert(Example.UserIdentity, %{
        user_info: %{"sub" => sub},
        oauth_tokens: %{},
        strategy: strategy_name,
        user_id: user.id
      })

    :ok
  end

  describe "sign_in/2" do
    test "it returns an error when registration is enabled" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)

      assert {:error, error} =
               Actions.sign_in(strategy, %{"user_info" => %{}, "oauth_tokens" => %{}}, [])

      assert Exception.message(error) =~ ~r/no such action :sign_in_with_oauth2/i
    end

    test "it signs in an existing user when registration is disabled" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)
      strategy = %{strategy | registration_enabled?: false}
      user = build_user()
      :ok = seed_identity(:oauth2, user, "user:#{user.id}")

      assert {:ok, signed_in_user} =
               Actions.sign_in(
                 strategy,
                 %{
                   "user_info" => %{
                     "nickname" => user.username,
                     "uid" => user.id,
                     "sub" => "user:#{user.id}"
                   },
                   "oauth_tokens" => %{
                     "access_token" => Ecto.UUID.generate(),
                     "expires_in" => 86_400,
                     "refresh_token" => Ecto.UUID.generate()
                   }
                 },
                 []
               )

      assert signed_in_user.id == user.id
      assert {:ok, claims} = Jwt.peek(signed_in_user.__metadata__.token)
      assert claims["sub"] =~ "user?id=#{user.id}"
    end

    test "it signs in an existing user when registration is disabled and sub is an integer" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)
      strategy = %{strategy | registration_enabled?: false}
      user = build_user()
      :ok = seed_identity(:oauth2, user, 1234)

      assert {:ok, signed_in_user} =
               Actions.sign_in(
                 strategy,
                 %{
                   "user_info" => %{
                     "nickname" => user.username,
                     "uid" => user.id,
                     "sub" => 1234
                   },
                   "oauth_tokens" => %{
                     "access_token" => Ecto.UUID.generate(),
                     "expires_in" => 86_400,
                     "refresh_token" => Ecto.UUID.generate()
                   }
                 },
                 []
               )

      assert signed_in_user.id == user.id

      assert {:ok, _claims} =
               Jwt.peek(signed_in_user.__metadata__.token)
    end

    test "it signs in an existing user with a registration-disabled strategy" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2_without_identity)
      user = build_user()
      :ok = seed_identity(:oauth2_without_identity, user, "user:#{user.id}")

      assert {:ok, signed_in_user} =
               Actions.sign_in(
                 strategy,
                 %{
                   "user_info" => %{
                     "nickname" => user.username,
                     "uid" => user.id,
                     "sub" => "user:#{user.id}"
                   },
                   "oauth_tokens" => %{
                     "access_token" => Ecto.UUID.generate(),
                     "expires_in" => 86_400,
                     "refresh_token" => Ecto.UUID.generate()
                   }
                 },
                 []
               )

      assert signed_in_user.id == user.id
      assert {:ok, claims} = Jwt.peek(signed_in_user.__metadata__.token)
      assert claims["sub"] =~ "user?id=#{user.id}"
    end

    test "it denies sign in for non-existing users when registration is disabled" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)
      strategy = %{strategy | registration_enabled?: false}

      assert {:error, error} =
               Actions.sign_in(
                 strategy,
                 %{
                   "user_info" => %{
                     "nickname" => username(),
                     "uid" => Ecto.UUID.generate(),
                     "sub" => "user:#{Ecto.UUID.generate()}"
                   },
                   "oauth_tokens" => %{
                     "access_token" => Ecto.UUID.generate(),
                     "expires_in" => 86_400,
                     "refresh_token" => Ecto.UUID.generate()
                   }
                 },
                 []
               )

      assert Exception.message(error) =~ ~r/authentication failed/i
    end
  end

  describe "register/2" do
    test "it registers a non-existing user when registration is enabled" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)

      username = username()
      id = Ecto.UUID.generate()

      assert {:ok, user} =
               Actions.register(
                 strategy,
                 %{
                   "user_info" => %{
                     "nickname" => username,
                     "uid" => id,
                     "sub" => "user:#{id}"
                   },
                   "oauth_tokens" => %{
                     "access_token" => Ecto.UUID.generate(),
                     "expires_in" => 86_400,
                     "refresh_token" => Ecto.UUID.generate()
                   }
                 },
                 []
               )

      assert to_string(user.username) == username
      assert {:ok, claims} = Jwt.peek(user.__metadata__.token)
      assert claims["sub"] =~ "user?id=#{user.id}"
    end

    test "it signs in a returning user matched by their existing identity" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)

      user = build_user()
      Ash.Seed.update!(user, %{confirmed_at: DateTime.utc_now()})
      sub = "user:#{user.id}"

      {:ok, _identity} =
        AshAuthentication.UserIdentity.Actions.upsert(Example.UserIdentity, %{
          user_info: %{"sub" => sub},
          oauth_tokens: %{},
          strategy: :oauth2,
          user_id: user.id
        })

      assert {:ok, signed_in_user} =
               Actions.register(
                 strategy,
                 %{
                   # A different nickname than the user's - matching is by `sub`,
                   # not by any provider-supplied attribute.
                   "user_info" => %{
                     "nickname" => username(),
                     "uid" => user.id,
                     "sub" => sub
                   },
                   "oauth_tokens" => %{
                     "access_token" => Ecto.UUID.generate(),
                     "expires_in" => 86_400,
                     "refresh_token" => Ecto.UUID.generate()
                   }
                 },
                 []
               )

      assert signed_in_user.id == user.id
      assert {:ok, claims} = Jwt.peek(signed_in_user.__metadata__.token)
      assert claims["sub"] =~ "user?id=#{user.id}"
    end

    test "it rejects a new identity that resolves to an existing account by an untrusted email" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)

      user = build_user()

      assert {:error, error} =
               Actions.register(
                 strategy,
                 %{
                   "user_info" => %{
                     "nickname" => to_string(user.username),
                     "uid" => Ecto.UUID.generate(),
                     "sub" => "user:#{Ecto.UUID.generate()}"
                   },
                   "oauth_tokens" => %{
                     "access_token" => Ecto.UUID.generate(),
                     "expires_in" => 86_400,
                     "refresh_token" => Ecto.UUID.generate()
                   }
                 },
                 []
               )

      assert Exception.message(error) =~ ~r/authentication failed/i
    end

    test "it requires confirmation, without touching the existing account, when `on_untrusted_email_match` is `:confirm`" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2_confirm_link)

      user = build_user()
      sub = "user:#{Ecto.UUID.generate()}"
      access_token = Ecto.UUID.generate()

      assert {:error, %AuthenticationFailed{} = error} =
               Actions.register(
                 strategy,
                 %{
                   "user_info" => %{
                     "nickname" => to_string(user.username),
                     "uid" => Ecto.UUID.generate(),
                     "sub" => sub
                   },
                   "oauth_tokens" => %{
                     "access_token" => access_token,
                     "expires_in" => 86_400,
                     "refresh_token" => Ecto.UUID.generate()
                   }
                 },
                 []
               )

      # The plug/controller can match on the inner reason to prompt the user to
      # check their email; no user record or provider tokens ride downstream.
      assert %ConfirmationRequired{} = error.caused_by

      # The existing account is untouched: the abort wrote no identity for this sub.
      assert {:ok, []} =
               Example.UserIdentity
               |> Ash.Query.filter(uid == ^sub)
               |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
               |> Ash.read()

      # A confirmation was issued, bound to the existing account, carrying the
      # pending identity link server-side.
      assert {:ok, tokens} =
               Example.Token
               |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
               |> Ash.read()

      assert link_token =
               Enum.find(tokens, &Map.has_key?(&1.extra_data || %{}, "__oauth_identity__"))

      assert link_token.subject == AshAuthentication.user_to_subject(user)
      payload = link_token.extra_data["__oauth_identity__"]
      assert payload["strategy"] == "oauth2_confirm_link"
      assert payload["user_info"]["sub"] == sub
      assert payload["oauth_tokens"]["access_token"] == access_token
    end

    test "confirming a link token links the provider to the existing account, and can't be replayed" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2_confirm_link)
      confirmation = confirmation_add_on()

      user = build_user()
      sub = "user:#{Ecto.UUID.generate()}"

      payload = %{
        "strategy" => "oauth2_confirm_link",
        "user_info" => %{"sub" => sub},
        "oauth_tokens" => %{"access_token" => Ecto.UUID.generate()}
      }

      {:ok, token} = Confirmation.confirmation_token_for_link(confirmation, user, payload, [])

      # Not linked until the recipient proves ownership by confirming.
      assert :error = UserResolver.fetch_identity(strategy, sub)

      assert {:ok, _confirmed} = Confirmation.Actions.confirm(confirmation, %{"confirm" => token})

      # The provider identity is now bound to the existing account.
      assert {:ok, identity} = UserResolver.fetch_identity(strategy, sub)
      assert identity.user_id == user.id

      # The confirmation is single-use: replaying the token is rejected.
      assert {:error, %InvalidToken{}} =
               Confirmation.Actions.confirm(confirmation, %{"confirm" => token})
    end

    test "it links a new identity to an existing account when the email is trusted" do
      {:ok, strategy} = Info.strategy(Example.User, :github)
      user = build_user()
      Ash.Seed.update!(user, %{confirmed_at: DateTime.utc_now()})

      assert {:ok, signed_in_user} =
               Actions.register(
                 strategy,
                 %{
                   "user_info" => %{
                     "nickname" => to_string(user.username),
                     "uid" => Ecto.UUID.generate(),
                     "sub" => "gh:#{Ecto.UUID.generate()}",
                     "email_verified" => true
                   },
                   "oauth_tokens" => %{
                     "access_token" => Ecto.UUID.generate(),
                     "expires_in" => 86_400,
                     "refresh_token" => Ecto.UUID.generate()
                   }
                 },
                 []
               )

      assert signed_in_user.id == user.id
    end

    test "it rejects linking a second identity for the same strategy" do
      {:ok, strategy} = Info.strategy(Example.User, :github)
      user = build_user()
      Ash.Seed.update!(user, %{confirmed_at: DateTime.utc_now()})
      :ok = seed_identity(:github, user, "gh:first")

      assert {:error, error} =
               Actions.register(
                 strategy,
                 %{
                   "user_info" => %{
                     "nickname" => to_string(user.username),
                     "uid" => Ecto.UUID.generate(),
                     "sub" => "gh:second",
                     "email_verified" => true
                   },
                   "oauth_tokens" => %{
                     "access_token" => Ecto.UUID.generate(),
                     "expires_in" => 86_400,
                     "refresh_token" => Ecto.UUID.generate()
                   }
                 },
                 []
               )

      assert Exception.message(error) =~ ~r/authentication failed/i
    end
  end
end
