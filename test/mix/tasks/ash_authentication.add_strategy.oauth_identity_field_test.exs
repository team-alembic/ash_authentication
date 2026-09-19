# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
defmodule Mix.Tasks.AshAuthentication.AddStrategy.OauthIdentityFieldTest do
  use ExUnit.Case

  import Igniter.Test

  @moduletag :igniter

  # `oauth2` and `oidc` are generic, so they need a provider name.
  @oauth_tasks [
    {"apple", []},
    {"auth0", []},
    {"dynamic_oidc", []},
    {"github", []},
    {"google", []},
    {"microsoft", []},
    {"oauth2", ["my_provider"]},
    {"oidc", ["my_provider"]},
    {"okta", []},
    {"slack", []}
  ]

  setup do
    igniter =
      test_project()
      |> Igniter.Project.Deps.add_dep({:simple_sat, ">= 0.0.0"})
      |> Igniter.compose_task("ash_authentication.install", ["--yes"])
      |> Igniter.Project.Formatter.remove_imported_dep(:ash_authentication)
      |> Igniter.Project.Formatter.remove_formatter_plugin(Spark.Formatter)
      |> apply_igniter!()

    [igniter: igniter]
  end

  for {task, args} <- @oauth_tasks do
    test "#{task} refuses a non-email identity field", %{igniter: igniter} do
      args = unquote(args) ++ ["--identity-field", "preferred_username"]

      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.#{unquote(task)}", args)
      |> assert_has_issue(&(&1 =~ "identity field :preferred_username"))
    end

    test "#{task} keys its register action on the email by default", %{igniter: igniter} do
      result =
        Igniter.compose_task(
          igniter,
          "ash_authentication.add_strategy.#{unquote(task)}",
          unquote(args)
        )

      assert result.issues == []
      assert diff(result) =~ "upsert_identity(:unique_email)"
    end
  end
end
