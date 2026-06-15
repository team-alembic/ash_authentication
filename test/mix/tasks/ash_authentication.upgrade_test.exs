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

  describe "require_identity_resource/2" do
    test "wires up the identity resource when one exists conventionally" do
      igniter =
        oauth2_project(
          strategy: """
          oauth2 :oauth2 do
            client_id fn _, _ -> {:ok, "client_id"} end
            client_secret fn _, _ -> {:ok, "client_secret"} end
            redirect_uri fn _, _ -> {:ok, "https://example.com"} end
            base_url fn _, _ -> {:ok, "https://example.com"} end
            authorize_url fn _, _ -> {:ok, "https://example.com/authorize"} end
            token_url fn _, _ -> {:ok, "https://example.com/token"} end
            user_url fn _, _ -> {:ok, "https://example.com/userinfo"} end
          end
          """,
          identity_resource?: true
        )

      igniter = Mix.Tasks.AshAuthentication.Upgrade.require_identity_resource(igniter, [])

      igniter
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |        identity_resource(Test.Accounts.UserIdentity)
      """)
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |        change(AshAuthentication.Strategy.OAuth2.IdentityChange)
      """)
    end

    test "generates and wires the identity resource when none exists" do
      igniter =
        oauth2_project(
          strategy: """
          github :github do
            client_id fn _, _ -> {:ok, "client_id"} end
            client_secret fn _, _ -> {:ok, "client_secret"} end
            redirect_uri fn _, _ -> {:ok, "https://example.com"} end
          end
          """,
          identity_resource?: false
        )

      igniter = Mix.Tasks.AshAuthentication.Upgrade.require_identity_resource(igniter, [])

      igniter
      |> assert_creates("lib/test/accounts/user_identity.ex", fn content ->
        assert content =~ "extensions: [AshAuthentication.UserIdentity]"
        assert content =~ "user_resource(Test.Accounts.User)"
      end)
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |        identity_resource(Test.Accounts.UserIdentity)
      """)
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |        change(AshAuthentication.Strategy.OAuth2.IdentityChange)
      """)
    end

    test "does not modify a strategy that already has an identity resource" do
      # Written pre-formatted: the upgrader re-renders any module it visits, so a
      # no-op only compares equal if the source is already in formatted style.
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

          create :register_with_oauth2 do
            argument(:user_info, :map, allow_nil?: false)
            argument(:oauth_tokens, :map, allow_nil?: false)
            upsert?(true)
            upsert_identity(:unique_email)

            change(AshAuthentication.GenerateTokenChange)
            change(AshAuthentication.Strategy.OAuth2.IdentityChange)
          end
        end

        authentication do
          tokens do
            enabled?(true)
            token_resource(Test.Accounts.Token)
            signing_secret(fn _, _ -> {:ok, "test_secret_that_is_at_least_32_bytes_long"} end)
          end

          strategies do
            oauth2 :oauth2 do
              client_id(fn _, _ -> {:ok, "client_id"} end)
              client_secret(fn _, _ -> {:ok, "client_secret"} end)
              redirect_uri(fn _, _ -> {:ok, "https://example.com"} end)
              base_url(fn _, _ -> {:ok, "https://example.com"} end)
              authorize_url(fn _, _ -> {:ok, "https://example.com/authorize"} end)
              token_url(fn _, _ -> {:ok, "https://example.com/token"} end)
              user_url(fn _, _ -> {:ok, "https://example.com/userinfo"} end)
              identity_resource(Test.Accounts.UserIdentity)
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

      identity_resource = """
      defmodule Test.Accounts.UserIdentity do
        use Ash.Resource,
          domain: Test.Accounts,
          extensions: [AshAuthentication.UserIdentity],
          data_layer: Ash.DataLayer.Ets

        user_identity do
          user_resource(Test.Accounts.User)
        end
      end
      """

      igniter =
        test_project(
          files: %{
            "lib/test/accounts/user.ex" => user_resource,
            "lib/test/accounts/token.ex" => token_resource,
            "lib/test/accounts/user_identity.ex" => identity_resource
          }
        )

      igniter = Mix.Tasks.AshAuthentication.Upgrade.require_identity_resource(igniter, [])

      assert_unchanged(igniter, "lib/test/accounts/user.ex")
    end
  end

  defp oauth2_project(opts) do
    strategy = Keyword.fetch!(opts, :strategy)
    identity_resource? = Keyword.get(opts, :identity_resource?, false)

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

        create :register_with_oauth2 do
          argument :user_info, :map, allow_nil?: false
          argument :oauth_tokens, :map, allow_nil?: false
          upsert? true
          upsert_identity :unique_email

          change AshAuthentication.GenerateTokenChange
        end

        create :register_with_github do
          argument :user_info, :map, allow_nil?: false
          argument :oauth_tokens, :map, allow_nil?: false
          upsert? true
          upsert_identity :unique_email

          change AshAuthentication.GenerateTokenChange
        end
      end

      authentication do
        tokens do
          enabled? true
          token_resource Test.Accounts.Token
          signing_secret fn _, _ -> {:ok, "test_secret_that_is_at_least_32_bytes_long"} end
        end

        strategies do
          #{strategy}
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

    identity_resource = """
    defmodule Test.Accounts.UserIdentity do
      use Ash.Resource,
        domain: Test.Accounts,
        extensions: [AshAuthentication.UserIdentity],
        data_layer: Ash.DataLayer.Ets

      user_identity do
        user_resource Test.Accounts.User
      end
    end
    """

    files =
      %{
        "lib/test/accounts/user.ex" => user_resource,
        "lib/test/accounts/token.ex" => token_resource
      }
      |> then(fn files ->
        if identity_resource? do
          Map.put(files, "lib/test/accounts/user_identity.ex", identity_resource)
        else
          files
        end
      end)

    test_project(files: files)
    |> Igniter.Project.Deps.add_dep({:simple_sat, ">= 0.0.0"})
  end
end
