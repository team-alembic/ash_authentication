# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
defmodule Mix.Tasks.AshAuthentication.InstallTest do
  use ExUnit.Case

  import Igniter.Test

  @moduletag :igniter

  setup(context) do
    igniter_args = Map.get(context, :igniter_args, [])

    igniter =
      test_project()
      |> Igniter.Project.Deps.add_dep({:simple_sat, ">= 0.0.0"})
      |> Igniter.compose_task("ash_authentication.install", ["--yes" | igniter_args])
      |> Igniter.Project.Formatter.remove_formatter_plugin(Spark.Formatter)

    [igniter: igniter]
  end

  test "installation is idempotent" do
    test_project()
    |> Igniter.Project.Deps.add_dep({:simple_sat, ">= 0.0.0"})
    |> Igniter.compose_task("ash_authentication.install", ["--yes"])
    |> apply_igniter!()
    |> Igniter.compose_task("ash_authentication.install", ["--yes"])
    |> assert_unchanged()
  end

  test "installation creates an accounts domain", %{igniter: igniter} do
    igniter
    |> assert_creates("lib/test/accounts.ex", """
    defmodule Test.Accounts do
      use Ash.Domain,
        otp_app: :test

      resources do
        resource(Test.Accounts.Token)
        resource(Test.Accounts.User)
      end
    end
    """)
  end

  @tag igniter_args: ["--accounts", "Test.Banana"]
  test "installation honours the accounts argument", %{igniter: igniter} do
    igniter
    |> assert_creates("lib/test/banana.ex", """
    defmodule Test.Banana do
      use Ash.Domain,
        otp_app: :test

      resources do
        resource(Test.Banana.Token)
        resource(Test.Banana.User)
      end
    end
    """)
    |> assert_creates("lib/test/banana/user.ex")
  end

  @tag igniter_args: ["--accounts", "Test.Banana", "--auth-strategy", "password"]
  test "installation hours the accounts and strategy options together", %{igniter: igniter} do
    assert igniter.issues == []
  end

  @tag igniter_args: ["--user", "Test.Accounts.Admin"]
  test "installation honours the user argument", %{igniter: igniter} do
    igniter
    |> assert_creates("lib/test/accounts/admin.ex")
  end

  @tag igniter_args: ["--token", "Test.Accounts.JWT"]
  test "installation honours the token argument", %{igniter: igniter} do
    igniter
    |> assert_creates("lib/test/accounts/jwt.ex")
  end

  test "installation creates a secrets module", %{igniter: igniter} do
    igniter
    |> assert_creates("lib/test/secrets.ex", """
    defmodule Test.Secrets do
      use AshAuthentication.Secret

      def secret_for([:authentication, :tokens, :signing_secret], Test.Accounts.User, _opts, _context) do
        Application.fetch_env(:test, :token_signing_secret)
      end
    end
    """)
  end

  test "installation adds the supervisor to the app", %{igniter: igniter} do
    igniter
    |> assert_has_patch("lib/test/application.ex", """
    8  |     children = [{AshAuthentication.Supervisor, [otp_app: :test]}]
    """)
  end

  test "installation adds config files", %{igniter: igniter} do
    igniter
    |> assert_creates("config/runtime.exs", """
    import Config

    if config_env() == :prod do
      config :test,
        token_signing_secret:
          System.get_env("TOKEN_SIGNING_SECRET") ||
            raise("Missing environment variable `TOKEN_SIGNING_SECRET`!")
    end
    """)

    # can't easily test this with the helpers we have.
    # we can make `assert_creates` take a function potentially
    # for now, this is simple enough that its almost testing `igniter`.
    # |> assert_creates("config/dev.exs", """
    # import Config
    # config :test, token_signing_secret: "kDL+MmXw8E0xbN//xYTowcR1tt5yCLSu"
    # """)
    # |> assert_creates("config/test.exs", """
    # import Config
    # config :test, token_signing_secret: "7vg4IwKCttu/eMU3PYPLCjrl277OlNvr"
    # """)
  end

  test "installation adds a user resource", %{igniter: igniter} do
    igniter
    |> assert_creates("lib/test/accounts/user.ex", """
    defmodule Test.Accounts.User do
      use Ash.Resource,
        otp_app: :test,
        domain: Test.Accounts,
        data_layer: AshPostgres.DataLayer,
        authorizers: [Ash.Policy.Authorizer],
        extensions: [AshAuthentication]

      postgres do
        table("users")
        repo(Test.Repo)
      end

      policies do
        bypass AshAuthentication.Checks.AshAuthenticationInteraction do
          authorize_if(always())
        end
      end

      authentication do
        add_ons do
          log_out_everywhere do
            apply_on_password_change?(true)
          end
        end

        tokens do
          enabled?(true)
          token_resource(Test.Accounts.Token)
          signing_secret(Test.Secrets)
          store_all_tokens?(true)
          require_token_presence_for_authentication?(true)
        end
      end

      attributes do
        uuid_primary_key(:id)
      end

      actions do
        defaults([:read])

        read :get_by_subject do
          description("Get a user by the subject claim in a JWT")
          argument(:subject, :string, allow_nil?: false)
          get?(true)
          prepare(AshAuthentication.Preparations.FilterBySubject)
        end
      end
    end
    """)
  end

  test "instalation adds a user token resource", %{igniter: igniter} do
    igniter
    |> assert_creates("lib/test/accounts/token.ex", """
    defmodule Test.Accounts.Token do
      use Ash.Resource,
        otp_app: :test,
        domain: Test.Accounts,
        data_layer: AshPostgres.DataLayer,
        authorizers: [Ash.Policy.Authorizer],
        extensions: [AshAuthentication.TokenResource]

      postgres do
        table("tokens")
        repo(Test.Repo)
      end

      policies do
        bypass AshAuthentication.Checks.AshAuthenticationInteraction do
          description("AshAuthentication can interact with the token resource")
          authorize_if(always())
        end
      end

      attributes do
        attribute :jti, :string do
          primary_key?(true)
          public?(true)
          allow_nil?(false)
          sensitive?(true)
        end

        attribute :subject, :string do
          allow_nil?(false)
          public?(true)
        end

        attribute :expires_at, :utc_datetime do
          allow_nil?(false)
          public?(true)
        end

        attribute :purpose, :string do
          allow_nil?(false)
          public?(true)
        end

        attribute :extra_data, :map do
          public?(true)
        end

        create_timestamp(:created_at)
        update_timestamp(:updated_at)
      end

      actions do
        defaults([:read])

        read :expired do
          description("Look up all expired tokens.")
          filter(expr(expires_at < now()))
        end

        read :get_token do
          description("Look up a token by JTI or token, and an optional purpose.")
          get?(true)
          argument(:token, :string, sensitive?: true)
          argument(:jti, :string, sensitive?: true)
          argument(:purpose, :string, sensitive?: false)

          prepare(AshAuthentication.TokenResource.GetTokenPreparation)
        end

        action :revoked?, :boolean do
          description("Returns true if a revocation token is found for the provided token")
          argument(:token, :string, sensitive?: true)
          argument(:jti, :string, sensitive?: true)

          run(AshAuthentication.TokenResource.IsRevoked)
        end

        create :revoke_token do
          description(
            "Revoke a token. Creates a revocation token corresponding to the provided token."
          )

          accept([:extra_data])
          argument(:token, :string, allow_nil?: false, sensitive?: true)

          change(AshAuthentication.TokenResource.RevokeTokenChange)
        end

        create :revoke_jti do
          description(
            "Revoke a token by JTI. Creates a revocation token corresponding to the provided jti."
          )

          accept([:extra_data])
          argument(:subject, :string, allow_nil?: false, sensitive?: true)
          argument(:jti, :string, allow_nil?: false, sensitive?: true)

          change(AshAuthentication.TokenResource.RevokeJtiChange)
        end

        create :store_token do
          description("Stores a token used for the provided purpose.")
          accept([:extra_data, :purpose])
          argument(:token, :string, allow_nil?: false, sensitive?: true)
          change(AshAuthentication.TokenResource.StoreTokenChange)
        end

        destroy :expunge_expired do
          description("Deletes expired tokens.")
          change(filter(expr(expires_at < now())))
        end

        update :revoke_all_stored_for_subject do
          description("Revokes all stored tokens for a specific subject.")
          accept([:extra_data])
          argument(:subject, :string, allow_nil?: false, sensitive?: true)
          change(AshAuthentication.TokenResource.RevokeAllStoredForSubjectChange)
        end
      end
    end
    """)
  end

  test "installation does not add filter_parameters without Phoenix", %{igniter: igniter} do
    diff = diff(igniter)
    refute diff =~ "filter_parameters"
  end

  describe "with Phoenix" do
    setup do
      igniter =
        test_project()
        |> Igniter.Project.Deps.add_dep({:simple_sat, ">= 0.0.0"})
        |> Igniter.create_new_file("lib/test_web.ex", """
        defmodule TestWeb do
        end
        """)
        |> apply_igniter!()
        |> Igniter.compose_task("ash_authentication.install", ["--yes"])
        |> Igniter.Project.Formatter.remove_formatter_plugin(Spark.Formatter)

      [igniter: igniter]
    end

    test "installation adds token to filter_parameters", %{igniter: igniter} do
      diff = diff(igniter)
      assert diff =~ "filter_parameters"
      assert diff =~ ~s|["password", "token"]|
    end
  end
end
