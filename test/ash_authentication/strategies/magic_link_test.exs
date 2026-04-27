# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.MagicLinkTest do
  @moduledoc false
  use DataCase, async: true

  import ExUnit.CaptureLog
  import Plug.Test

  alias AshAuthentication.{Info, Jwt, Plug, Strategy, Strategy.MagicLink}

  doctest MagicLink

  describe "request_token_for/2" do
    test "it generates a sign in token" do
      user = build_user()
      strategy = Info.strategy!(Example.User, :magic_link)

      assert {:ok, token} = MagicLink.request_token_for(strategy, user)

      assert {:ok, claims} = Jwt.peek(token)
      assert claims["act"] == to_string(strategy.sign_in_action_name)
    end
  end

  describe "actions" do
    test "with registration enabled" do
      strategy =
        Info.strategy!(Example.UserWithRegisterMagicLink, :magic_link)

      log =
        capture_log(fn ->
          MagicLink.Actions.request(
            strategy,
            %{"email" => "hello@example.com"},
            []
          )
        end)

      token =
        log
        |> String.split("Magic link request for hello@example.com, token \"", parts: 2)
        |> Enum.at(1)
        |> String.split("\"", parts: 2)
        |> Enum.at(0)

      assert {:ok,
              %Example.UserWithRegisterMagicLink{
                email: %Ash.CiString{string: "hello@example.com"}
              }} =
               MagicLink.Actions.sign_in(strategy, %{"token" => token}, [])
    end

    test "with registration enabled and an invalid token" do
      strategy =
        Info.strategy!(Example.UserWithRegisterMagicLink, :magic_link)

      log =
        capture_log(fn ->
          MagicLink.Actions.request(
            strategy,
            %{"email" => "hello@example.com"},
            []
          )
        end)

      token =
        log
        |> String.split("Magic link request for hello@example.com, token \"", parts: 2)
        |> Enum.at(1)
        |> String.split("\"", parts: 2)
        |> Enum.at(0)

      assert {:error,
              %AshAuthentication.Errors.AuthenticationFailed{
                caused_by: %Ash.Error.Forbidden{
                  errors: [%AshAuthentication.Errors.InvalidToken{type: :magic_link}]
                }
              }} = MagicLink.Actions.sign_in(strategy, %{"token" => token <> "a"}, [])
    end

    test "when the single-use revoke fails, the upsert rolls back and no user is persisted" do
      strategy =
        Info.strategy!(Example.UserWithRegisterMagicLink, :magic_link)

      log =
        capture_log(fn ->
          MagicLink.Actions.request(
            strategy,
            %{"email" => "raced@example.com"},
            []
          )
        end)

      token =
        log
        |> String.split("Magic link request for raced@example.com, token \"", parts: 2)
        |> Enum.at(1)
        |> String.split("\"", parts: 2)
        |> Enum.at(0)

      # Simulate a concurrent request that already committed the revocation.
      {:ok, token_resource} =
        Info.authentication_tokens_token_resource(Example.UserWithRegisterMagicLink)

      :ok =
        AshAuthentication.TokenResource.Actions.revoke(token_resource, token,
          store_all_tokens?: true
        )

      assert {:error, _} = MagicLink.Actions.sign_in(strategy, %{"token" => token}, [])

      # The upsert must have rolled back — no user record exists for this email.
      import Ecto.Query

      assert Example.Repo.aggregate(
               from(u in "user_with_register_magic_link",
                 where: u.email == "raced@example.com"
               ),
               :count
             ) == 0
    end

    test "cannot upsert against an unconfirmed user by default" do
      strategy =
        Info.strategy!(Example.UserWithRegisterMagicLink, :magic_link)

      log =
        capture_log(fn ->
          MagicLink.Actions.request(
            strategy,
            %{"email" => "hello@example.com"},
            []
          )
        end)

      token =
        log
        |> String.split("Magic link request for hello@example.com, token \"", parts: 2)
        |> Enum.at(1)
        |> String.split("\"", parts: 2)
        |> Enum.at(0)

      assert {:ok,
              %Example.UserWithRegisterMagicLink{
                email: %Ash.CiString{string: "hello@example.com"}
              } = user} =
               MagicLink.Actions.sign_in(strategy, %{"token" => token}, [])

      Ash.Seed.update!(user, %{confirmed_at: nil})

      log =
        capture_log(fn ->
          MagicLink.Actions.request(
            strategy,
            %{"email" => "hello@example.com"},
            []
          )
        end)

      token =
        log
        |> String.split("Magic link request for hello@example.com, token \"", parts: 2)
        |> Enum.at(1)
        |> String.split("\"", parts: 2)
        |> Enum.at(0)

      assert {:error,
              %AshAuthentication.Errors.AuthenticationFailed{
                caused_by: %Ash.Error.Forbidden{
                  errors: [%AshAuthentication.Errors.CannotConfirmUnconfirmedUser{}]
                }
              }} =
               MagicLink.Actions.sign_in(strategy, %{"token" => token}, [])
    end
  end
end
