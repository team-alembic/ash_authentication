# SPDX-FileCopyrightText: 2025 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Totp.ReplayProtectionTest do
  @moduledoc false
  use DataCase

  alias AshAuthentication.{
    Info,
    Strategy.Totp.Actions
  }

  describe "replay protection" do
    test "same code cannot be used twice" do
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      {:ok, user_with_secret} = Actions.setup(strategy, %{user: user}, [])
      code = NimbleTOTP.verification_code(user_with_secret.totp_secret)

      assert {:ok, _signed_in_user} =
               Actions.sign_in(
                 strategy,
                 %{strategy.identity_field => user_with_secret.email, "code" => code},
                 []
               )

      assert {:error, _error} =
               Actions.sign_in(
                 strategy,
                 %{strategy.identity_field => user_with_secret.email, "code" => code},
                 []
               )
    end

    test "code from future period is rejected until that period" do
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      {:ok, user_with_secret} = Actions.setup(strategy, %{user: user}, [])

      future_time = System.system_time(:second) + strategy.period + 1

      future_code =
        NimbleTOTP.verification_code(
          user_with_secret.totp_secret,
          time: future_time,
          period: strategy.period
        )

      assert {:error, _error} =
               Actions.sign_in(
                 strategy,
                 %{strategy.identity_field => user_with_secret.email, "code" => future_code},
                 []
               )
    end

    test "concurrent sign-in attempts with same code - only one should succeed" do
      user = build_user_with_totp()
      {:ok, strategy} = Info.strategy(Example.UserWithTotp, :totp)

      {:ok, user_with_secret} = Actions.setup(strategy, %{user: user}, [])
      code = NimbleTOTP.verification_code(user_with_secret.totp_secret)

      tasks =
        for _ <- 1..5 do
          Task.async(fn ->
            Actions.sign_in(
              strategy,
              %{strategy.identity_field => user_with_secret.email, "code" => code},
              []
            )
          end)
        end

      results = Task.await_many(tasks, 10_000)

      successes = Enum.count(results, &match?({:ok, _}, &1))
      failures = Enum.count(results, &match?({:error, _}, &1))

      assert successes == 1, "Expected exactly 1 success, got #{successes}"
      assert failures == 4, "Expected exactly 4 failures, got #{failures}"
    end
  end
end
