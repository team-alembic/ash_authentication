# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
defmodule Mix.Tasks.AshAuthentication.UpgradeTest do
  use ExUnit.Case

  import Igniter.Test

  @moduletag :igniter

  describe "add_remember_me_to_magic_link_sign_in/2" do
    test "adds remember_me argument and change to magic link sign-in action" do
      user_resource = """
      defmodule Test.Accounts.User do
        use Ash.Resource,
          domain: Test.Accounts,
          extensions: [AshAuthentication],
          data_layer: Ash.DataLayer.Ets

        attributes do
          uuid_primary_key :id
          attribute :email, :ci_string, allow_nil?: false, public?: true
        end

        identities do
          identity :unique_email, [:email]
        end

        actions do
          defaults [:read]

          create :sign_in_with_magic_link do
            description "Sign in or register a user with magic link."

            argument :token, :string do
              description "The token from the magic link that was sent to the user"
              allow_nil? false
            end

            upsert? true
            upsert_identity :unique_email
            upsert_fields [:email]

            change AshAuthentication.Strategy.MagicLink.SignInChange

            metadata :token, :string do
              allow_nil? false
            end
          end
        end

        authentication do
          tokens do
            enabled? true
            token_resource Test.Accounts.Token
            signing_secret fn _, _ -> {:ok, "test_secret_that_is_at_least_32_bytes_long"} end
          end

          strategies do
            magic_link do
              identity_field :email
              sender fn _user, _token, _opts -> :ok end
            end

            remember_me do
              enabled? true
            end
          end
        end
      end
      """

      token_resource = """
      defmodule Test.Accounts.Token do
        use Ash.Resource,
          domain: Test.Accounts,
          extensions: [AshAuthentication.TokenResource],
          data_layer: Ash.DataLayer.Ets

        token do
          api Test.Accounts
        end
      end
      """

      domain = """
      defmodule Test.Accounts do
        use Ash.Domain

        resources do
          resource Test.Accounts.User
          resource Test.Accounts.Token
        end
      end
      """

      igniter =
        test_project(
          files: %{
            "lib/test/accounts/user.ex" => user_resource,
            "lib/test/accounts/token.ex" => token_resource,
            "lib/test/accounts.ex" => domain
          }
        )

      igniter =
        Mix.Tasks.AshAuthentication.Upgrade.add_remember_me_to_magic_link_sign_in(igniter, [])

      igniter
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |      argument :remember_me, :boolean do
      + |        description("Whether to generate a remember me token")
      + |        allow_nil?(true)
      """)
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |      change(
      + |        {AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenChange,
      + |         strategy_name: :remember_me}
      + |      )
      """)
    end

    test "does not add duplicate argument if remember_me argument already exists" do
      user_resource = """
      defmodule Test.Accounts.User do
        use Ash.Resource,
          domain: Test.Accounts,
          extensions: [AshAuthentication],
          data_layer: Ash.DataLayer.Ets

        attributes do
          uuid_primary_key(:id)
          attribute(:email, :ci_string, allow_nil?: false, public?: true)
        end

        identities do
          identity(:unique_email, [:email])
        end

        actions do
          defaults([:read])

          create :sign_in_with_magic_link do
            description("Sign in or register a user with magic link.")

            argument :token, :string do
              description("The token from the magic link that was sent to the user")
              allow_nil?(false)
            end

            argument :remember_me, :boolean do
              description("Whether to generate a remember me token")
              allow_nil?(true)
            end

            upsert?(true)
            upsert_identity(:unique_email)
            upsert_fields([:email])

            change(AshAuthentication.Strategy.MagicLink.SignInChange)

            change(
              {AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenChange,
               strategy_name: :remember_me}
            )

            metadata :token, :string do
              allow_nil?(false)
            end
          end
        end

        authentication do
          tokens do
            enabled?(true)
            token_resource(Test.Accounts.Token)
            signing_secret(fn _, _ -> {:ok, "test_secret_that_is_at_least_32_bytes_long"} end)
          end

          strategies do
            magic_link do
              identity_field(:email)
              sender(fn _user, _token, _opts -> :ok end)
            end

            remember_me do
              enabled?(true)
            end
          end
        end
      end
      """

      token_resource = """
      defmodule Test.Accounts.Token do
        use Ash.Resource,
          domain: Test.Accounts,
          extensions: [AshAuthentication.TokenResource],
          data_layer: Ash.DataLayer.Ets

        token do
          api(Test.Accounts)
        end
      end
      """

      domain = """
      defmodule Test.Accounts do
        use Ash.Domain

        resources do
          resource(Test.Accounts.User)
          resource(Test.Accounts.Token)
        end
      end
      """

      igniter =
        test_project(
          files: %{
            "lib/test/accounts/user.ex" => user_resource,
            "lib/test/accounts/token.ex" => token_resource,
            "lib/test/accounts.ex" => domain
          }
        )

      igniter =
        Mix.Tasks.AshAuthentication.Upgrade.add_remember_me_to_magic_link_sign_in(igniter, [])

      assert_unchanged(igniter, "lib/test/accounts/user.ex")
    end

    test "does not modify resources without remember_me strategy" do
      user_resource = """
      defmodule Test.Accounts.User do
        use Ash.Resource,
          domain: Test.Accounts,
          extensions: [AshAuthentication],
          data_layer: Ash.DataLayer.Ets

        attributes do
          uuid_primary_key :id
          attribute :email, :ci_string, allow_nil?: false, public?: true
        end

        identities do
          identity :unique_email, [:email]
        end

        actions do
          defaults [:read]

          create :sign_in_with_magic_link do
            description "Sign in or register a user with magic link."

            argument :token, :string do
              description "The token from the magic link that was sent to the user"
              allow_nil? false
            end

            upsert? true
            upsert_identity :unique_email
            upsert_fields [:email]

            change AshAuthentication.Strategy.MagicLink.SignInChange

            metadata :token, :string do
              allow_nil? false
            end
          end
        end

        authentication do
          tokens do
            enabled? true
            token_resource Test.Accounts.Token
            signing_secret fn _, _ -> {:ok, "test_secret_that_is_at_least_32_bytes_long"} end
          end

          strategies do
            magic_link do
              identity_field :email
              sender fn _user, _token, _opts -> :ok end
            end
          end
        end
      end
      """

      token_resource = """
      defmodule Test.Accounts.Token do
        use Ash.Resource,
          domain: Test.Accounts,
          extensions: [AshAuthentication.TokenResource],
          data_layer: Ash.DataLayer.Ets

        token do
          api Test.Accounts
        end
      end
      """

      domain = """
      defmodule Test.Accounts do
        use Ash.Domain

        resources do
          resource Test.Accounts.User
          resource Test.Accounts.Token
        end
      end
      """

      igniter =
        test_project(
          files: %{
            "lib/test/accounts/user.ex" => user_resource,
            "lib/test/accounts/token.ex" => token_resource,
            "lib/test/accounts.ex" => domain
          }
        )

      igniter =
        Mix.Tasks.AshAuthentication.Upgrade.add_remember_me_to_magic_link_sign_in(igniter, [])

      assert_unchanged(igniter, "lib/test/accounts/user.ex")
    end

    test "does not modify resources without magic_link strategy" do
      user_resource = """
      defmodule Test.Accounts.User do
        use Ash.Resource,
          domain: Test.Accounts,
          extensions: [AshAuthentication],
          data_layer: Ash.DataLayer.Ets

        attributes do
          uuid_primary_key :id
          attribute :email, :ci_string, allow_nil?: false, public?: true
          attribute :hashed_password, :string, allow_nil?: false, sensitive?: true
        end

        identities do
          identity :unique_email, [:email]
        end

        actions do
          defaults [:read, :create]
        end

        authentication do
          tokens do
            enabled? true
            token_resource Test.Accounts.Token
            signing_secret fn _, _ -> {:ok, "test_secret_that_is_at_least_32_bytes_long"} end
          end

          strategies do
            password :password do
              identity_field :email
            end

            remember_me do
              enabled? true
            end
          end
        end
      end
      """

      token_resource = """
      defmodule Test.Accounts.Token do
        use Ash.Resource,
          domain: Test.Accounts,
          extensions: [AshAuthentication.TokenResource],
          data_layer: Ash.DataLayer.Ets

        token do
          api Test.Accounts
        end
      end
      """

      domain = """
      defmodule Test.Accounts do
        use Ash.Domain

        resources do
          resource Test.Accounts.User
          resource Test.Accounts.Token
        end
      end
      """

      igniter =
        test_project(
          files: %{
            "lib/test/accounts/user.ex" => user_resource,
            "lib/test/accounts/token.ex" => token_resource,
            "lib/test/accounts.ex" => domain
          }
        )

      igniter =
        Mix.Tasks.AshAuthentication.Upgrade.add_remember_me_to_magic_link_sign_in(igniter, [])

      assert_unchanged(igniter, "lib/test/accounts/user.ex")
    end
  end
end
