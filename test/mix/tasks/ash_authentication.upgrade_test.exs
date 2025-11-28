# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
defmodule Mix.Tasks.AshAuthentication.UpgradeTest do
  use ExUnit.Case

  alias Mix.Tasks.AshAuthentication.Upgrade

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
        Upgrade.add_remember_me_to_magic_link_sign_in(igniter, [])

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
        Upgrade.add_remember_me_to_magic_link_sign_in(igniter, [])

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
        Upgrade.add_remember_me_to_magic_link_sign_in(igniter, [])

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
        Upgrade.add_remember_me_to_magic_link_sign_in(igniter, [])

      assert_unchanged(igniter, "lib/test/accounts/user.ex")
    end
  end

  describe "fix_google_hd_field/2" do
    test "replaces google_hd string with hd in map access" do
      test_project(
        files: %{
          "lib/my_app/accounts/user.ex" => """
          defmodule MyApp.Accounts.User do
            def register_with_google(changeset) do
              user_info = get_argument(changeset, :user_info)
              hd = user_info["google_hd"]
              email = user_info["email"]
              {hd, email}
            end
          end
          """
        }
      )
      |> Upgrade.fix_google_hd_field([])
      |> assert_has_patch("lib/my_app/accounts/user.ex", """
      - |      hd = user_info["google_hd"]
      + |      hd = user_info["hd"]
      """)
    end

    test "replaces google_hd string in pattern matching" do
      test_project(
        files: %{
          "lib/my_app/accounts/user.ex" => """
          defmodule MyApp.Accounts.User do
            def handle_user_info(%{"google_hd" => hd, "email" => email}) do
              {hd, email}
            end
          end
          """
        }
      )
      |> Upgrade.fix_google_hd_field([])
      |> assert_has_patch("lib/my_app/accounts/user.ex", """
      - |  def handle_user_info(%{"google_hd" => hd, "email" => email}) do
      + |  def handle_user_info(%{"hd" => hd, "email" => email}) do
      """)
    end

    test "replaces google_hd in Map.get calls" do
      test_project(
        files: %{
          "lib/my_app/accounts/user.ex" => """
          defmodule MyApp.Accounts.User do
            def get_hosted_domain(user_info) do
              Map.get(user_info, "google_hd")
            end
          end
          """
        }
      )
      |> Upgrade.fix_google_hd_field([])
      |> assert_has_patch("lib/my_app/accounts/user.ex", """
      - |    Map.get(user_info, "google_hd")
      + |    Map.get(user_info, "hd")
      """)
    end

    test "does not modify files without google_hd" do
      test_project(
        files: %{
          "lib/my_app/accounts/user.ex" => """
          defmodule MyApp.Accounts.User do
            def get_email(user_info) do
              user_info["email"]
            end
          end
          """
        }
      )
      |> Upgrade.fix_google_hd_field([])
      |> assert_unchanged("lib/my_app/accounts/user.ex")
    end

    test "adds notice about email_verified boolean change" do
      test_project()
      |> Upgrade.fix_google_hd_field([])
      |> assert_has_notice(&String.contains?(&1, "email_verified"))
    end
  end
end
