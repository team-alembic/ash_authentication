# credo:disable-for-this-file Credo.Check.Design.AliasUsage
defmodule Mix.Tasks.AshAuthentication.InstallTest do
  use ExUnit.Case

  import Igniter.Test

  setup do
    igniter =
      test_project()
      |> Igniter.Project.Deps.add_dep({:simple_sat, ">= 0.0.0"})
      |> Igniter.compose_task("ash_authentication.install", ["--yes"])
      # This can be removed when https://github.com/hrzndhrn/rewrite/issues/39 is addressed (in igniter too)
      |> Igniter.Project.Formatter.remove_imported_dep(:ash_authentication)
      |> Igniter.Project.Formatter.remove_formatter_plugin(Spark.Formatter)

    [igniter: igniter]
  end

  test "installation creates a secrets module", %{igniter: igniter} do
    igniter
    |> assert_creates("lib/test/secrets.ex", """
    defmodule Test.Secrets do
      use AshAuthentication.Secret

      def secret_for([:authentication, :tokens, :signing_secret], Test.Accounts.User, _opts) do
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
        authorizers: [Ash.Policy.Authorizer],
        extensions: [AshAuthentication],
        data_layer: AshPostgres.DataLayer

      policies do
        bypass AshAuthentication.Checks.AshAuthenticationInteraction do
          authorize_if(always())
        end

        policy always() do
          forbid_if(always())
        end
      end

      authentication do
        tokens do
          enabled?(true)
          token_resource(Test.Accounts.Token)
          signing_secret(Test.Secrets)
        end
      end

      postgres do
        table("users")
        repo(Test.Repo)
      end

      attributes do
        uuid_primary_key(:id)
      end

      actions do
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
        authorizers: [Ash.Policy.Authorizer],
        extensions: [AshAuthentication.TokenResource],
        data_layer: AshPostgres.DataLayer

      policies do
        bypass AshAuthentication.Checks.AshAuthenticationInteraction do
          description("AshAuthentication can interact with the token resource")
          authorize_if(always())
        end

        policy always() do
          description("No one aside from AshAuthentication can interact with the tokens resource.")
          forbid_if(always())
        end
      end

      postgres do
        table("tokens")
        repo(Test.Repo)
      end

      attributes do
        uuid_primary_key(:id)

        attribute :jti, :string do
          primary_key?(true)
          public?(true)
          allow_nil?(false)
          sensitive?(true)
        end

        attribute :subject, :string do
          allow_nil?(false)
        end

        attribute :expires_at, :utc_datetime do
          allow_nil?(false)
        end

        attribute :purpose, :string do
          allow_nil?(false)
          public?(true)
        end

        attribute :extra_data, :map do
          public?(true)
        end

        timestamps()
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

        action :revoked? do
          description("Returns true if a revocation token is found for the provided token")
          argument(:token, :string, sensitive?: true, allow_nil?: false)
          argument(:jti, :string, sensitive?: true, allow_nil?: false)

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
      end
    end
    """)
  end
end
