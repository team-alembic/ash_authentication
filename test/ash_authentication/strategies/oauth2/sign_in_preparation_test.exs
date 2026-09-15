# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.OAuth2.SignInPreparationTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.{
    Errors.AuthenticationFailed,
    Info,
    Jwt,
    Strategy.OAuth2,
    Strategy.OAuth2.Actions,
    Strategy.OAuth2.SignInPreparation,
    Strategy.OAuth2.UserResolver
  }

  alias Spark.Error.DslError

  require Ash.Query

  defp seed_account(attrs) do
    Ash.Seed.seed!(Example.UserWithOauth2Email, attrs)
  end

  # `Actions.sign_in` wraps the preparation's rejection in an outer
  # `AuthenticationFailed`, so dig out the message the preparation recorded.
  defp rejection_message(%AuthenticationFailed{
         caused_by: %{module: SignInPreparation, message: message}
       }),
       do: message

  defp rejection_message(%AuthenticationFailed{caused_by: caused_by}),
    do: rejection_message(caused_by)

  defp rejection_message(%{errors: errors}) when is_list(errors),
    do: Enum.find_value(errors, &rejection_message/1)

  defp rejection_message(_other), do: nil

  defp identities_for(account) do
    Example.UserWithOauth2EmailIdentity
    |> Ash.Query.filter(user_id == ^account.id)
    |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
    |> Ash.read!()
  end

  defp sign_in(resource, strategy_name, user_info) do
    {:ok, strategy} = Info.strategy(resource, strategy_name)

    Actions.sign_in(
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

  describe "a non-email filter with a trusted `email_verified` claim" do
    test "it refuses to attach the sign-in to the account the username matched" do
      victim = seed_account(%{username: "victim-login", email: "victim-real@example.com"})
      sub = "slack:#{Ecto.UUID.generate()}"

      assert {:error, %AuthenticationFailed{} = error} =
               sign_in(Example.UserWithOauth2Email, :slack, %{
                 "sub" => sub,
                 "nickname" => "victim-login",
                 "email" => "attacker@evil.com",
                 "email_verified" => true
               })

      assert rejection_message(error) =~ ~r/could not be verified/i
      assert {:ok, strategy} = Info.strategy(Example.UserWithOauth2Email, :slack)
      assert :error = UserResolver.fetch_identity(strategy, sub)
      assert [] = identities_for(victim)
    end

    test "it writes no identity row, so a second attempt is refused in the same way" do
      victim = seed_account(%{username: "victim-login", email: "victim-real@example.com"})
      sub = "slack:#{Ecto.UUID.generate()}"

      user_info = %{
        "sub" => sub,
        "nickname" => "victim-login",
        "email" => "attacker@evil.com",
        "email_verified" => true
      }

      assert {:error, %AuthenticationFailed{}} =
               sign_in(Example.UserWithOauth2Email, :slack, user_info)

      assert [] = identities_for(victim)

      assert {:error, %AuthenticationFailed{}} =
               sign_in(Example.UserWithOauth2Email, :slack, user_info)

      assert [] = identities_for(victim)
    end

    test "it refuses when the matched account has no email at all" do
      seed_account(%{username: "no-email-login", email: nil})

      assert {:error, %AuthenticationFailed{} = error} =
               sign_in(Example.UserWithOauth2Email, :slack, %{
                 "sub" => "slack:#{Ecto.UUID.generate()}",
                 "nickname" => "no-email-login",
                 "email" => "attacker@evil.com",
                 "email_verified" => true
               })

      assert rejection_message(error) =~ ~r/could not be verified/i
    end

    test "it refuses when the provider supplies no email" do
      seed_account(%{username: "no-claim-login", email: "person@example.com"})

      assert {:error, %AuthenticationFailed{}} =
               sign_in(Example.UserWithOauth2Email, :slack, %{
                 "sub" => "slack:#{Ecto.UUID.generate()}",
                 "nickname" => "no-claim-login",
                 "email_verified" => true
               })
    end

    test "it attaches when the verified email is the matched account's email" do
      account = seed_account(%{username: "genuine-login", email: "genuine@example.com"})
      sub = "slack:#{Ecto.UUID.generate()}"

      assert {:ok, signed_in} =
               sign_in(Example.UserWithOauth2Email, :slack, %{
                 "sub" => sub,
                 "nickname" => "genuine-login",
                 "email" => "genuine@example.com",
                 "email_verified" => true
               })

      assert signed_in.id == account.id
      assert {:ok, strategy} = Info.strategy(Example.UserWithOauth2Email, :slack)
      assert {:ok, identity} = UserResolver.fetch_identity(strategy, sub)
      assert identity.user_id == account.id
    end

    test "it signs a returning user back in by their `(strategy, sub)` identity" do
      account = seed_account(%{username: "returning-login", email: "returning@example.com"})
      sub = "slack:#{Ecto.UUID.generate()}"

      assert {:ok, _first} =
               sign_in(Example.UserWithOauth2Email, :slack, %{
                 "sub" => sub,
                 "nickname" => "returning-login",
                 "email" => "returning@example.com",
                 "email_verified" => true
               })

      # The email no longer matters: the identity resolves the account.
      assert {:ok, returning} =
               sign_in(Example.UserWithOauth2Email, :slack, %{
                 "sub" => sub,
                 "nickname" => "returning-login",
                 "email" => "changed@example.com",
                 "email_verified" => false
               })

      assert returning.id == account.id
    end
  end

  describe "an email filter with a trusted `email_verified` claim" do
    test "it attaches the sign-in and issues a token for the matched account" do
      account = seed_account(%{email: "person@example.com"})
      sub = "auth0:#{Ecto.UUID.generate()}"

      assert {:ok, signed_in} =
               sign_in(Example.UserWithOauth2Email, :auth0, %{
                 "sub" => sub,
                 "email" => "person@example.com",
                 "email_verified" => true
               })

      assert signed_in.id == account.id
      assert {:ok, claims} = Jwt.peek(signed_in.__metadata__.token)
      assert claims["sub"] == AshAuthentication.user_to_subject(account)

      assert {:ok, strategy} = Info.strategy(Example.UserWithOauth2Email, :auth0)
      assert {:ok, identity} = UserResolver.fetch_identity(strategy, sub)
      assert identity.user_id == account.id
    end

    test "it attaches across a difference of case" do
      account = seed_account(%{email: "Person@Example.COM"})

      assert {:ok, signed_in} =
               sign_in(Example.UserWithOauth2Email, :auth0, %{
                 "sub" => "auth0:#{Ecto.UUID.generate()}",
                 "email" => "person@example.com",
                 "email_verified" => true
               })

      assert signed_in.id == account.id
    end
  end

  describe "an untrusted `email_verified` claim" do
    # `Example.User` has no email attribute at all, and the `:oauth2_untrusted`
    # strategy leaves `trust_email_verified?` at its `false` default.
    test "it refuses to attach the sign-in to the account the username matched" do
      user = build_user()
      {:ok, strategy} = Info.strategy(Example.User, :oauth2_untrusted)
      sub = "oauth2:#{Ecto.UUID.generate()}"

      assert {:error, %AuthenticationFailed{} = error} =
               sign_in(Example.User, :oauth2_untrusted, %{
                 "sub" => sub,
                 "nickname" => to_string(user.username),
                 "email" => "attacker@evil.com",
                 "email_verified" => true
               })

      assert rejection_message(error) =~ ~r/could not be verified/i
      assert :error = UserResolver.fetch_identity(strategy, sub)
    end
  end

  describe "UserResolver.email_matches_account?/3" do
    test "it is false when `email_field` names no attribute of the record" do
      {:ok, strategy} = Info.strategy(Example.UserWithOauth2Email, :slack)
      account = seed_account(%{email: "person@example.com"})

      refute UserResolver.email_matches_account?(
               %{strategy | email_field: :nickname},
               account,
               %{"email" => "person@example.com", "email_verified" => true}
             )
    end

    test "it is false when `email_field` is unset" do
      {:ok, strategy} = Info.strategy(Example.UserWithOauth2Email, :slack)
      account = seed_account(%{email: "person@example.com"})

      refute UserResolver.email_matches_account?(
               %{strategy | email_field: nil},
               account,
               %{"email" => "person@example.com", "email_verified" => true}
             )
    end
  end

  describe "the `email_field` option" do
    test "it defaults to `:email` on the base strategy and on those built from it" do
      assert {:ok, %{email_field: :email}} = Info.strategy(Example.User, :oauth2)
      assert {:ok, %{email_field: :email}} = Info.strategy(Example.User, :github)
      assert {:ok, %{email_field: :email}} = Info.strategy(Example.User, :oidc)
      assert {:ok, %{email_field: :email}} = Info.strategy(Example.User, :sso)
      assert {:ok, %{email_field: :email}} = Info.strategy(Example.UserWithOauth2Email, :slack)
    end

    test "the transformer refuses a trusted sign-in strategy whose field names no attribute" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2_untrusted)
      dsl_state = Example.User.spark_dsl_config()

      assert {:error, %DslError{} = error} =
               OAuth2.Transformer.validate_email_field(
                 dsl_state,
                 %{strategy | trust_email_verified?: true}
               )

      assert error.path == [:authentication, :strategies, :oauth2_untrusted, :email_field]
      assert Exception.message(error) =~ "not an attribute of this resource"
    end

    test "the transformer accepts the same strategy when the field names an attribute" do
      {:ok, strategy} = Info.strategy(Example.User, :oauth2_untrusted)
      dsl_state = Example.User.spark_dsl_config()

      assert :ok =
               OAuth2.Transformer.validate_email_field(
                 dsl_state,
                 %{strategy | trust_email_verified?: true, email_field: :username}
               )
    end

    test "the transformer ignores a register strategy, which compares matched values" do
      {:ok, strategy} = Info.strategy(Example.User, :github)
      dsl_state = Example.User.spark_dsl_config()

      assert strategy.registration_enabled?
      assert strategy.trust_email_verified?
      assert is_nil(Ash.Resource.Info.attribute(Example.User, :email))
      assert :ok = OAuth2.Transformer.validate_email_field(dsl_state, strategy)
    end
  end
end
