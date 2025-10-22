# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
defmodule Mix.Tasks.AshAuthentication.Gen.ApiKeyTest do
  use ExUnit.Case

  import Igniter.Test

  @moduletag :igniter

  setup do
    igniter =
      test_project()
      |> Igniter.Project.Deps.add_dep({:simple_sat, ">= 0.0.0"})
      |> Igniter.compose_task("ash_authentication.install", ["--yes"])
      # These can be removed when https://github.com/hrzndhrn/rewrite/issues/39 is addressed (in igniter too)
      |> Igniter.Project.Formatter.remove_imported_dep(:ash_authentication)
      |> Igniter.Project.Formatter.remove_formatter_plugin(Spark.Formatter)
      |> apply_igniter!()

    [igniter: igniter]
  end

  test "adds the api_key strategy to the user", %{igniter: igniter} do
    igniter
    |> Igniter.compose_task("ash_authentication.gen.api_key")
    |> assert_has_patch("lib/test/accounts/user.ex", """
    + | api_key :api_key do
    + |   api_key_relationship(:valid_api_keys)
    + |   api_key_hash_attribute(:api_key_hash)
    + | end
    """)
    |> assert_has_patch("lib/test/accounts/user.ex", """
    + | has_many :valid_api_keys, Test.Accounts.ApiKey do
    + |   filter(expr(valid))
    + | end
    """)
  end

  test "creates the api key resource", %{igniter: igniter} do
    igniter
    |> Igniter.compose_task("ash_authentication.gen.api_key")
    |> assert_creates("lib/test/accounts/api_key.ex", """
    defmodule Test.Accounts.ApiKey do
      use Ash.Resource,
        otp_app: :test,
        domain: Test.Accounts,
        data_layer: AshPostgres.DataLayer,
        authorizers: [Ash.Policy.Authorizer]

      attributes do
        uuid_primary_key(:id)

        attribute :api_key_hash, :binary do
          allow_nil?(false)
          sensitive?(true)
        end

        attribute :expires_at, :utc_datetime_usec do
          allow_nil?(false)
        end
      end

      relationships do
        belongs_to(:user, Test.Accounts.User)
      end

      actions do
        defaults([:read, :destroy])

        create :create do
          primary?(true)
          accept([:user_id, :expires_at])

          change(
            {AshAuthentication.Strategy.ApiKey.GenerateApiKey, prefix: :test, hash: :api_key_hash}
          )
        end
      end

      postgres do
        table("api_keys")
        repo(Test.Repo)
      end

      identities do
        identity(:unique_api_key, [:api_key_hash])
      end

      calculations do
        calculate(:valid, :boolean, expr(expires_at > now()))
      end

      policies do
        bypass AshAuthentication.Checks.AshAuthenticationInteraction do
          authorize_if(always())
        end
      end
    end
    """)
  end
end
