# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
defmodule Mix.Tasks.AshAuthentication.AddStrategy.DynamicOidcTest do
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

  test "the connection resource has one `use Ash.Resource`, with the extension", %{
    igniter: igniter
  } do
    igniter =
      Igniter.compose_task(igniter, "ash_authentication.add_strategy.dynamic_oidc", [])

    source =
      igniter.rewrite
      |> Rewrite.source!("lib/test/accounts/oidc_connection.ex")
      |> Rewrite.Source.get(:content)

    assert [_one] = Regex.scan(~r/use Ash\.Resource/, source)
    assert source =~ ~r/extensions: \[[^\]]*AshAuthentication\.OidcConnection/
    assert source =~ "oidc_connection do"
    assert source =~ "domain(Test.Accounts)"
    assert source =~ ~r/postgres do\s+table\("oidc_connections"\)\s+repo\(Test.Repo\)/
  end
end
