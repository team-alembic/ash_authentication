# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
defmodule Mix.Tasks.AshAuthenticatioin.Gen.MagicLinkTest do
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

  test "makes hashed_password optional", %{igniter: igniter} do
    igniter
    |> Igniter.compose_task("ash_authentication.gen.password")
    |> apply_igniter!()
    |> Igniter.compose_task("ash_authentication.gen.magic_link")
    |> assert_has_patch("lib/test/accounts/user.ex", """
      |    attribute :hashed_password, :string do
    - |      allow_nil?(false)
      |      sensitive?(true)
      |    end
    """)
    |> assert_has_patch("lib/test/accounts/user.ex", """
    + |   action :request_magic_link do
    + |     argument :email, :ci_string do
    + |       allow_nil?(false)
    + |     end
    + |
    + |     run(AshAuthentication.Strategy.MagicLink.Request)
    + |   end
    """)
    |> assert_has_patch("lib/test/accounts/user.ex", """
    + |     magic_link do
    + |       identity_field(:email)
    + |       registration_enabled?(true)
    + |       require_interaction?(true)
    + |
    + |       sender(Test.Accounts.User.Senders.SendMagicLinkEmail)
    + |     end
    """)
  end
end
