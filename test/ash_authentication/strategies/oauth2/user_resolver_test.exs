# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.UserResolverTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.{
    Errors.AuthenticationFailed,
    Info,
    Jwt,
    Strategy.OAuth2.Actions,
    Strategy.OAuth2.UserResolver
  }

  require Ash.Query

  defp seed_account(attrs) do
    Ash.Seed.seed!(Example.UserWithOauth2Email, attrs)
  end

  # `Actions.register` wraps the resolver's rejection in an outer
  # `AuthenticationFailed`, so dig out the message the resolver itself recorded.
  defp rejection_message(%AuthenticationFailed{
         caused_by: %{module: UserResolver, message: message}
       }),
       do: message

  defp rejection_message(%AuthenticationFailed{caused_by: caused_by}),
    do: rejection_message(caused_by)

  defp rejection_message(%{errors: errors}) when is_list(errors),
    do: Enum.find_value(errors, &rejection_message/1)

  defp rejection_message(_other), do: nil

  defp reload(account) do
    Example.UserWithOauth2Email
    |> Ash.Query.filter(id == ^account.id)
    |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
    |> Ash.read_one!()
  end

  defp register(strategy_name, user_info) do
    {:ok, strategy} = Info.strategy(Example.UserWithOauth2Email, strategy_name)

    Actions.register(
      strategy,
      %{
        "user_info" => user_info,
        "oauth_tokens" => %{
          "access_token" => Ecto.UUID.generate(),
          "expires_in" => 86_400,
          "refresh_token" => Ecto.UUID.generate()
        }
      },
      []
    )
  end

  describe "a non-email `upsert_identity` with a trusted `email_verified` claim" do
    test "it refuses to attach the sign-in to the account the username matched" do
      victim = seed_account(%{username: "victim-login", email: "victim-real@example.com"})
      sub = "google:#{Ecto.UUID.generate()}"

      assert {:error, %AuthenticationFailed{} = error} =
               register(:google, %{
                 "sub" => sub,
                 "nickname" => "victim-login",
                 "email" => "attacker@evil.com",
                 "email_verified" => true
               })

      assert rejection_message(error) =~ ~r/could not be verified/i

      # The victim's account is untouched and no identity binds the provider to it.
      assert to_string(reload(victim).email) == "victim-real@example.com"
      assert {:ok, strategy} = Info.strategy(Example.UserWithOauth2Email, :google)
      assert :error = UserResolver.fetch_identity(strategy, sub)
    end

    test "it refuses when the matched account has no email at all" do
      seed_account(%{username: "victim-login", email: nil})

      assert {:error, %AuthenticationFailed{} = error} =
               register(:google, %{
                 "sub" => "google:#{Ecto.UUID.generate()}",
                 "nickname" => "victim-login",
                 "email" => "attacker@evil.com",
                 "email_verified" => true
               })

      assert rejection_message(error) =~ ~r/could not be verified/i
    end

    test "it refuses when neither the provider nor the matched account has an email" do
      seed_account(%{username: "victim-login", email: nil})

      assert {:error, %AuthenticationFailed{}} =
               register(:google, %{
                 "sub" => "google:#{Ecto.UUID.generate()}",
                 "nickname" => "victim-login",
                 "email_verified" => true
               })
    end
  end

  describe "a non-email `upsert_identity` with an untrusted `email_verified` claim" do
    # `Example.User` keys `register_with_oauth2` on `:username`, and the
    # `:oauth2` strategy leaves `trust_email_verified?` at its `false` default.
    test "it refuses to attach the sign-in to the account the username matched" do
      user = build_user()
      {:ok, strategy} = Info.strategy(Example.User, :oauth2)
      sub = "oauth2:#{Ecto.UUID.generate()}"

      assert {:error, %AuthenticationFailed{} = error} =
               Actions.register(
                 strategy,
                 %{
                   "user_info" => %{
                     "sub" => sub,
                     "nickname" => to_string(user.username),
                     "email" => "attacker@evil.com",
                     "email_verified" => true
                   },
                   "oauth_tokens" => %{
                     "access_token" => Ecto.UUID.generate(),
                     "expires_in" => 86_400
                   }
                 },
                 []
               )

      assert rejection_message(error) =~ ~r/could not be verified/i
      assert :error = UserResolver.fetch_identity(strategy, sub)
    end
  end

  describe "an email-keyed `upsert_identity`" do
    test "it attaches a sign-in whose verified email matched the account" do
      account = seed_account(%{email: "person@example.com"})
      sub = "github:#{Ecto.UUID.generate()}"

      assert {:ok, signed_in} =
               register(:github, %{
                 "sub" => sub,
                 "email" => "person@example.com",
                 "email_verified" => true
               })

      assert signed_in.id == account.id
      assert {:ok, claims} = Jwt.peek(signed_in.__metadata__.token)
      assert claims["sub"] =~ "#{account.id}"

      assert {:ok, strategy} = Info.strategy(Example.UserWithOauth2Email, :github)
      assert {:ok, identity} = UserResolver.fetch_identity(strategy, sub)
      assert identity.user_id == account.id
    end

    test "it attaches across a difference of case and surrounding whitespace" do
      account = seed_account(%{email: "Person@Example.COM"})

      assert {:ok, signed_in} =
               register(:github, %{
                 "sub" => "github:#{Ecto.UUID.generate()}",
                 "email" => "  person@example.com  ",
                 "email_verified" => true
               })

      assert signed_in.id == account.id
    end

    test "it registers a new account when the verified email matches nothing" do
      account = seed_account(%{email: "person@example.com"})
      sub = "github:#{Ecto.UUID.generate()}"

      assert {:ok, registered} =
               register(:github, %{
                 "sub" => sub,
                 "email" => "someone-else@example.com",
                 "email_verified" => true
               })

      refute registered.id == account.id
      assert to_string(registered.email) == "someone-else@example.com"

      assert {:ok, strategy} = Info.strategy(Example.UserWithOauth2Email, :github)
      assert {:ok, identity} = UserResolver.fetch_identity(strategy, sub)
      assert identity.user_id == registered.id
    end

    test "it registers a first-time user when no account exists" do
      sub = "github:#{Ecto.UUID.generate()}"

      assert {:ok, registered} =
               register(:github, %{
                 "sub" => sub,
                 "email" => "newcomer@example.com",
                 "email_verified" => true
               })

      assert to_string(registered.email) == "newcomer@example.com"
      assert {:ok, strategy} = Info.strategy(Example.UserWithOauth2Email, :github)
      assert {:ok, identity} = UserResolver.fetch_identity(strategy, sub)
      assert identity.user_id == registered.id
    end

    test "it signs a returning user back in by their `(strategy, sub)` identity" do
      sub = "github:#{Ecto.UUID.generate()}"

      assert {:ok, registered} =
               register(:github, %{
                 "sub" => sub,
                 "email" => "returning@example.com",
                 "email_verified" => true
               })

      assert {:ok, returning} =
               register(:github, %{
                 "sub" => sub,
                 "email" => "returning@example.com",
                 "email_verified" => true
               })

      assert returning.id == registered.id
    end
  end
end
