defmodule AshAuthentication.Strategy.OAuth2.ActionsTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.{Info, Jwt, Strategy.OAuth2.Actions}

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

    test "it signs in an existing user when registration and identity are disabled" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2_without_identity)
      user = build_user()

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

    test "it signs in an existing user when registration is enabled" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)

      user = build_user()

      Ash.Seed.update!(user, %{confirmed_at: DateTime.utc_now()})

      assert {:ok, signed_in_user} =
               Actions.register(
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
  end
end
