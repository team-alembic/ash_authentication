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

  describe "add_brute_force_protection/2" do
    test "adds brute_force_strategy to password and magic_link strategies and composes audit_log task" do
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

      igniter = Upgrade.add_brute_force_protection(igniter, [])

      igniter
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |      brute_force_strategy({:audit_log, :audit_log})
      """)
      |> assert_has_patch("lib/test/accounts/user.ex", """
      + |    add_ons do
      + |      audit_log do
      """)
      |> assert_has_notice(&String.contains?(&1, "Brute-force Protection"))
    end

    test "uses existing audit_log name when one is already configured" do
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

          add_ons do
            audit_log :my_audit_log do
              audit_log_resource Test.Accounts.AuditLog
            end
          end

          strategies do
            password :password do
              identity_field :email
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

      igniter = Upgrade.add_brute_force_protection(igniter, [])

      assert_has_patch(igniter, "lib/test/accounts/user.ex", """
      + |      brute_force_strategy({:audit_log, :my_audit_log})
      """)
    end

    test "does not duplicate brute_force_strategy when already present" do
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

          add_ons do
            audit_log do
              audit_log_resource Test.Accounts.AuditLog
            end
          end

          strategies do
            password :password do
              identity_field :email
              brute_force_strategy {:audit_log, :audit_log}
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

      igniter = Upgrade.add_brute_force_protection(igniter, [])

      assert_unchanged(igniter, "lib/test/accounts/user.ex")
    end

    test "does not modify resources without password or magic_link strategies" do
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
            api_key do
              api_key_relationship :api_keys
              api_key_hash_attribute :api_key_hash
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

      igniter = Upgrade.add_brute_force_protection(igniter, [])

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

      igniter = Upgrade.require_identity_resource(igniter, [])

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

      igniter = Upgrade.require_identity_resource(igniter, [])

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

      igniter = Upgrade.require_identity_resource(igniter, [])

      assert_unchanged(igniter, "lib/test/accounts/user.ex")
    end
  end

  describe "move_audit_log_ip_salt/2" do
    test "moves a string salt into the consuming application" do
      test_project(
        files: %{
          "config/config.exs" => """
          import Config
          config :ash_authentication, audit_log_ip_salt: "the existing salt"
          """
        }
      )
      |> Upgrade.move_audit_log_ip_salt([])
      |> assert_has_patch("config/config.exs", """
      - |config :ash_authentication, audit_log_ip_salt: "the existing salt"
      + |config :test, audit_log_ip_salt: "the existing salt"
      """)
    end

    test "preserves a `System.fetch_env!/1` value" do
      test_project(
        files: %{
          "config/runtime.exs" => """
          import Config
          config :ash_authentication, audit_log_ip_salt: System.fetch_env!("AUDIT_LOG_IP_SALT")
          """
        }
      )
      |> Upgrade.move_audit_log_ip_salt([])
      |> assert_has_patch("config/runtime.exs", """
      - |config :ash_authentication, audit_log_ip_salt: System.fetch_env!("AUDIT_LOG_IP_SALT")
      + |config :test, audit_log_ip_salt: System.fetch_env!("AUDIT_LOG_IP_SALT")
      """)
    end

    test "preserves a `{module, function, arguments}` value" do
      test_project(
        files: %{
          "config/config.exs" => """
          import Config
          config :ash_authentication, audit_log_ip_salt: {MyApp.Secrets, :ip_salt, []}
          """
        }
      )
      |> Upgrade.move_audit_log_ip_salt([])
      |> assert_has_patch("config/config.exs", """
      + |config :test, audit_log_ip_salt: {MyApp.Secrets, :ip_salt, []}
      """)
    end

    test "moves the three argument form" do
      test_project(
        files: %{
          "config/config.exs" => """
          import Config
          config :ash_authentication, :audit_log_ip_salt, "the existing salt"
          """
        }
      )
      |> Upgrade.move_audit_log_ip_salt([])
      |> assert_has_patch("config/config.exs", """
      - |config :ash_authentication, :audit_log_ip_salt, "the existing salt"
      + |config :test, :audit_log_ip_salt, "the existing salt"
      """)
    end

    test "leaves other `:ash_authentication` keys behind" do
      test_project(
        files: %{
          "config/config.exs" => """
          import Config

          config :ash_authentication,
            audit_log_ip_salt: "the existing salt",
            suppress_sensitive_field_warnings?: true
          """
        }
      )
      |> Upgrade.move_audit_log_ip_salt([])
      |> assert_has_patch("config/config.exs", """
      - |  audit_log_ip_salt: "the existing salt",
      """)
      |> assert_has_patch("config/config.exs", """
      + |config :test, audit_log_ip_salt: "the existing salt"
      """)
    end

    test "migrates every config file which sets the salt" do
      igniter =
        test_project(
          files: %{
            "config/dev.exs" => """
            import Config
            config :ash_authentication, audit_log_ip_salt: "the dev salt"
            """,
            "config/test.exs" => """
            import Config
            config :ash_authentication, audit_log_ip_salt: "the test salt"
            """
          }
        )
        |> Upgrade.move_audit_log_ip_salt([])

      igniter
      |> assert_has_patch("config/dev.exs", """
      + |config :test, audit_log_ip_salt: "the dev salt"
      """)
      |> assert_has_patch("config/test.exs", """
      + |config :test, audit_log_ip_salt: "the test salt"
      """)
    end

    test "finds a salt nested inside a `config_env/0` branch" do
      test_project(
        files: %{
          "config/runtime.exs" => """
          import Config

          if config_env() == :prod do
            config :ash_authentication, audit_log_ip_salt: "the prod salt"
          end
          """
        }
      )
      |> Upgrade.move_audit_log_ip_salt([])
      |> assert_has_patch("config/runtime.exs", """
      + |  config :test, audit_log_ip_salt: "the prod salt"
      """)
    end

    test "does nothing when the consuming application already sets the salt" do
      test_project(
        files: %{
          "config/config.exs" => """
          import Config
          config :ash_authentication, audit_log_ip_salt: "the old salt"
          config :test, audit_log_ip_salt: "the new salt"
          """
        }
      )
      |> Upgrade.move_audit_log_ip_salt([])
      |> assert_unchanged("config/config.exs")
    end

    test "does not move the salt when it is already nested in a `config_env/0` branch" do
      test_project(
        files: %{
          "config/config.exs" => """
          import Config
          config :ash_authentication, audit_log_ip_salt: "the old salt"
          """,
          "config/runtime.exs" => """
          import Config

          if config_env() == :prod do
            config :test, audit_log_ip_salt: "the new salt"
          end
          """
        }
      )
      |> Upgrade.move_audit_log_ip_salt([])
      |> assert_unchanged("config/config.exs")
    end

    test "leaves a `:secret` fallback alone" do
      test_project(
        files: %{
          "config/config.exs" => """
          import Config
          config :ash_authentication, secret: "a secret used as the salt"
          """
        }
      )
      |> Upgrade.move_audit_log_ip_salt([])
      |> assert_unchanged("config/config.exs")
    end

    test "does nothing when no salt is configured" do
      test_project()
      |> Upgrade.move_audit_log_ip_salt([])
      |> assert_unchanged()
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

  describe "strip_dead_oidc_options/2" do
    defp user_resource_content(igniter) do
      igniter.rewrite
      |> Rewrite.source!("lib/test/accounts/user.ex")
      |> Rewrite.Source.get(:content)
    end

    defp oidc_project(strategies) do
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

        actions do
          defaults [:read]
        end

        authentication do
          tokens do
            enabled? true
            token_resource Test.Accounts.Token
            signing_secret fn _, _ -> {:ok, "test_secret_that_is_at_least_32_bytes_long"} end
          end

          strategies do
      #{strategies}
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

      test_project(
        files: %{
          "lib/test/accounts/user.ex" => user_resource,
          "lib/test/accounts/token.ex" => token_resource,
          "lib/test/accounts.ex" => domain
        }
      )
    end

    test "removes the discovery-supplied URLs and `auth_method` from an auth0 block" do
      igniter =
        """
            auth0 do
              client_id fn _, _ -> {:ok, "id"} end
              client_secret fn _, _ -> {:ok, "secret"} end
              redirect_uri fn _, _ -> {:ok, "http://localhost:4000/auth"} end
              base_url fn _, _ -> {:ok, "https://example.auth0.com"} end
              authorize_url fn _, _ -> {:ok, "https://example.auth0.com/authorize"} end
              token_url fn _, _ -> {:ok, "https://example.auth0.com/oauth/token"} end
              user_url fn _, _ -> {:ok, "https://example.auth0.com/userinfo"} end
              auth_method :client_secret_post
            end
        """
        |> oidc_project()
        |> Upgrade.strip_dead_oidc_options([])

      content = user_resource_content(igniter)

      refute content =~ "authorize_url"
      refute content =~ "token_url"
      refute content =~ "user_url"
      refute content =~ "auth_method"

      # Discovery cannot supply these, so they stay.
      assert content =~ "base_url"
      assert content =~ "client_id"
      assert content =~ "client_secret"
      assert content =~ "redirect_uri"
    end

    test "removes `auth_method` from an oidc block but keeps the URLs on oauth2" do
      igniter =
        """
            oidc do
              client_id fn _, _ -> {:ok, "id"} end
              client_secret fn _, _ -> {:ok, "secret"} end
              redirect_uri fn _, _ -> {:ok, "http://localhost:4000/auth"} end
              base_url fn _, _ -> {:ok, "https://example.com"} end
              auth_method :client_secret_post
            end

            oauth2 do
              client_id fn _, _ -> {:ok, "id"} end
              client_secret fn _, _ -> {:ok, "secret"} end
              redirect_uri fn _, _ -> {:ok, "http://localhost:4000/auth"} end
              authorize_url fn _, _ -> {:ok, "https://example.com/authorize"} end
              token_url fn _, _ -> {:ok, "https://example.com/token"} end
              user_url fn _, _ -> {:ok, "https://example.com/userinfo"} end
              auth_method :client_secret_post
              trusted_audiences fn _, _ -> {:ok, ["aud"]} end
            end
        """
        |> oidc_project()
        |> Upgrade.strip_dead_oidc_options([])

      content = user_resource_content(igniter)

      # `oauth2` has no ID token, so `trusted_audiences` goes. `auth_method` is
      # the live setting there, so it stays, along with the three URLs.
      refute content =~ "trusted_audiences"
      assert content =~ "auth_method(:client_secret_post)"
      assert content =~ "authorize_url"
      assert content =~ "token_url"
      assert content =~ "user_url"

      # The `oidc` block keeps only one `auth_method`, the `oauth2` one.
      assert content |> String.split("auth_method") |> length() == 2
    end

    test "leaves a resource with no oauth2 strategies alone" do
      igniter =
        """
            password :password do
              identity_field :email
            end
        """
        |> oidc_project()
        |> Upgrade.strip_dead_oidc_options([])

      assert_unchanged(igniter)
    end
  end
end
