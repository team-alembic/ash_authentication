# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

# credo:disable-for-this-file Credo.Check.Design.AliasUsage
defmodule Mix.Tasks.AshAuthentication.AddStrategy.WebauthnTest do
  use ExUnit.Case

  import Igniter.Test

  @moduletag :igniter

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

  test "adds wax_ to deps", %{igniter: igniter} do
    igniter
    |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])
    |> assert_has_patch("mix.exs", """
    + |      {:wax_, "~> 0.7"},
    """)
  end

  test "creates the credential resource", %{igniter: igniter} do
    igniter
    |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])
    |> assert_creates("lib/test/accounts/web_authn_credential.ex")
  end

  test "credential resource has the WebAuthn-specific attributes", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    diff = diff(result)
    assert diff =~ "credential_id"
    assert diff =~ "AshAuthentication.Strategy.WebAuthn.CoseKey"
    assert diff =~ "sign_count"
    assert diff =~ "label"
  end

  test "credential resource has a belongs_to user relationship", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    assert diff(result) =~ "belongs_to :user"
  end

  test "credential resource has the AshAuthenticationInteraction policy bypass", %{
    igniter: igniter
  } do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    assert diff(result) =~ "AshAuthentication.Checks.AshAuthenticationInteraction"
  end

  test "credential resource registers Ash.Policy.Authorizer", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    assert diff(result) =~ "authorizers: [Ash.Policy.Authorizer]"
  end

  test "adds the has_many :webauthn_credentials relationship to the user", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    assert diff(result) =~ "has_many(:webauthn_credentials, Test.Accounts.WebAuthnCredential)"
  end

  test "wires rp_id, rp_name, origin, and identity_field through the Secrets module", %{
    igniter: igniter
  } do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    diff = diff(result)
    assert diff =~ "webauthn :webauthn"
    assert diff =~ "rp_id(Test.Secrets)"
    assert diff =~ "rp_name(Test.Secrets)"
    assert diff =~ "origin(Test.Secrets)"
    assert diff =~ "identity_field(:email)"
  end

  test "extends the Secrets module with clauses for the WebAuthn options", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    diff = diff(result, path: "lib/test/secrets.ex")
    assert diff =~ "[:authentication, :strategies, :webauthn, :rp_id]"
    assert diff =~ "[:authentication, :strategies, :webauthn, :rp_name]"
    assert diff =~ "[:authentication, :strategies, :webauthn, :origin]"
    assert diff =~ "Application.fetch_env(:test, :webauthn_rp_id)"
    assert diff =~ "Application.fetch_env(:test, :webauthn_rp_name)"
    assert diff =~ "Application.fetch_env(:test, :webauthn_origin)"
  end

  test "seeds dev.exs with sensible defaults", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    diff = diff(result, path: "config/dev.exs")
    assert diff =~ "webauthn_rp_id: \"localhost\""
    assert diff =~ "webauthn_rp_name: \"Test\""
    assert diff =~ "webauthn_origin: \"http://localhost:4000\""
  end

  test "seeds test.exs with sensible defaults", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    diff = diff(result, path: "config/test.exs")
    assert diff =~ "webauthn_rp_id: \"localhost\""
    assert diff =~ "webauthn_rp_name: \"Test\""
    assert diff =~ "webauthn_origin: \"http://localhost:4000\""
  end

  test "configures runtime.exs to read env vars in :prod", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    diff = diff(result, path: "config/runtime.exs")
    assert diff =~ ~s|webauthn_rp_id: System.get_env("WEBAUTHN_RP_ID")|
    assert diff =~ ~s|webauthn_rp_name: System.get_env("WEBAUTHN_RP_NAME")|
    assert diff =~ ~s|webauthn_origin: System.get_env("WEBAUTHN_ORIGIN")|
  end
end
