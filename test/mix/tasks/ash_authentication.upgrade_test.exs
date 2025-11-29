# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule Mix.Tasks.AshAuthentication.UpgradeTest do
  use ExUnit.Case

  alias Mix.Tasks.AshAuthentication.Upgrade

  import Igniter.Test

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
