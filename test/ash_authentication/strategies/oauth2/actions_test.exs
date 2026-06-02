# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.ActionsTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.{Info, Jwt, Strategy.OAuth2.Actions, UserIdentity}

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
