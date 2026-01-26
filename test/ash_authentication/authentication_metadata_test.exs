# SPDX-FileCopyrightText: 2024 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.AuthenticationMetadataTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.{Info, Strategy}

  describe "TOTP sign-in metadata" do
    test "sets authentication_strategies to [:totp]" do
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      {:ok, user_with_secret} = Strategy.action(strategy, :setup, %{user: user}, [])
      code = NimbleTOTP.verification_code(user_with_secret.totp_secret)

      {:ok, signed_in_user} =
        Strategy.action(
          strategy,
          :sign_in,
          %{strategy.identity_field => user_with_secret.email, "code" => code},
          []
        )

      assert signed_in_user.__metadata__.authentication_strategies == [:totp]
    end

    test "sets totp_verified_at to current time" do
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      {:ok, user_with_secret} = Strategy.action(strategy, :setup, %{user: user}, [])
      code = NimbleTOTP.verification_code(user_with_secret.totp_secret)

      before_sign_in = DateTime.utc_now()

      {:ok, signed_in_user} =
        Strategy.action(
          strategy,
          :sign_in,
          %{strategy.identity_field => user_with_secret.email, "code" => code},
          []
        )

      after_sign_in = DateTime.utc_now()

      assert %DateTime{} = signed_in_user.__metadata__.totp_verified_at

      assert DateTime.compare(signed_in_user.__metadata__.totp_verified_at, before_sign_in) in [
               :gt,
               :eq
             ]

      assert DateTime.compare(signed_in_user.__metadata__.totp_verified_at, after_sign_in) in [
               :lt,
               :eq
             ]
    end

    test "metadata is set alongside token" do
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      {:ok, user_with_secret} = Strategy.action(strategy, :setup, %{user: user}, [])
      code = NimbleTOTP.verification_code(user_with_secret.totp_secret)

      {:ok, signed_in_user} =
        Strategy.action(
          strategy,
          :sign_in,
          %{strategy.identity_field => user_with_secret.email, "code" => code},
          []
        )

      assert signed_in_user.__metadata__.token
      assert signed_in_user.__metadata__.authentication_strategies
      assert signed_in_user.__metadata__.totp_verified_at
    end
  end

  describe "password sign-in metadata" do
    test "sets authentication_strategies to [:password]" do
      user = build_user()
      strategy = Info.strategy!(Example.User, :password)

      {:ok, signed_in_user} =
        Strategy.action(
          strategy,
          :sign_in,
          %{
            username: user.username,
            password: user.__metadata__.password
          }
        )

      assert signed_in_user.__metadata__.authentication_strategies == [:password]
    end

    test "metadata is set alongside token" do
      user = build_user()
      strategy = Info.strategy!(Example.User, :password)

      {:ok, signed_in_user} =
        Strategy.action(
          strategy,
          :sign_in,
          %{
            username: user.username,
            password: user.__metadata__.password
          }
        )

      assert signed_in_user.__metadata__.token
      assert signed_in_user.__metadata__.authentication_strategies
    end

    test "sign_in tokens do not set authentication_strategies" do
      user = build_user()
      strategy = Info.strategy!(Example.User, :password)

      {:ok, signed_in_user} =
        Strategy.action(
          strategy,
          :sign_in,
          %{
            username: user.username,
            password: user.__metadata__.password
          },
          context: [token_type: :sign_in]
        )

      assert signed_in_user.__metadata__.token
      refute Map.has_key?(signed_in_user.__metadata__, :authentication_strategies)
    end
  end

  describe "metadata behaviour" do
    test "sign-in queries return fresh records with new metadata" do
      # Note: In-memory metadata is NOT preserved through database queries.
      # The sign-in action queries the database, returning a fresh record.
      # Metadata accumulation for 2FA flows happens through token claims,
      # not through in-memory record metadata.
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      {:ok, user_with_secret} = Strategy.action(strategy, :setup, %{user: user}, [])
      code = NimbleTOTP.verification_code(user_with_secret.totp_secret)

      {:ok, signed_in_user} =
        Strategy.action(
          strategy,
          :sign_in,
          %{strategy.identity_field => user_with_secret.email, "code" => code},
          []
        )

      # Fresh sign-in should have only the strategy used for this sign-in
      assert signed_in_user.__metadata__.authentication_strategies == [:totp]
    end

    test "multiple sign-ins each set their own strategy" do
      user = build_user()
      password_strategy = Info.strategy!(Example.User, :password)

      # First sign-in with password
      {:ok, signed_in_user_1} =
        Strategy.action(
          password_strategy,
          :sign_in,
          %{
            username: user.username,
            password: user.__metadata__.password
          }
        )

      # Second sign-in with password
      {:ok, signed_in_user_2} =
        Strategy.action(
          password_strategy,
          :sign_in,
          %{
            username: user.username,
            password: user.__metadata__.password
          }
        )

      # Each sign-in sets its own metadata independently
      assert signed_in_user_1.__metadata__.authentication_strategies == [:password]
      assert signed_in_user_2.__metadata__.authentication_strategies == [:password]
    end
  end
end
