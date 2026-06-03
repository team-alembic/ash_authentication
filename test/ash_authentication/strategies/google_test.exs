# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.GoogleTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.{Info, Strategy.OAuth2.Actions}

  describe "register/2" do
    test "rejects registration when email_verified is false" do
      {:ok, strategy} = Info.strategy(Example.User, :google)
      id = Ecto.UUID.generate()

      assert {:error, error} =
               Actions.register(
                 strategy,
                 %{
                   user_info: %{
                     "nickname" => username(),
                     "uid" => id,
                     "sub" => "user:#{id}",
                     "email_verified" => false
                   },
                   oauth_tokens: %{
                     "access_token" => Ecto.UUID.generate(),
                     "expires_in" => 86_400,
                     "refresh_token" => Ecto.UUID.generate()
                   }
                 },
                 []
               )

      assert Exception.message(error) =~ ~r/authentication failed/i
    end

    test "rejects registration when email_verified is absent" do
      {:ok, strategy} = Info.strategy(Example.User, :google)
      id = Ecto.UUID.generate()

      assert {:error, error} =
               Actions.register(
                 strategy,
                 %{
                   user_info: %{
                     "nickname" => username(),
                     "uid" => id,
                     "sub" => "user:#{id}"
                   },
                   oauth_tokens: %{
                     "access_token" => Ecto.UUID.generate(),
                     "expires_in" => 86_400,
                     "refresh_token" => Ecto.UUID.generate()
                   }
                 },
                 []
               )

      assert Exception.message(error) =~ ~r/authentication failed/i
    end

    test "allows registration when email_verified is true" do
      {:ok, strategy} = Info.strategy(Example.User, :google)
      id = Ecto.UUID.generate()

      assert {:ok, _user} =
               Actions.register(
                 strategy,
                 %{
                   user_info: %{
                     "nickname" => username(),
                     "uid" => id,
                     "sub" => "user:#{id}",
                     "email_verified" => true
                   },
                   oauth_tokens: %{
                     "access_token" => Ecto.UUID.generate(),
                     "expires_in" => 86_400,
                     "refresh_token" => Ecto.UUID.generate()
                   }
                 },
                 []
               )
    end
  end
end
