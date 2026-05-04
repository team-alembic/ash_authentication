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

  @args ["--rp-id", "example.com", "--rp-name", "Test App"]

  test "adds wax_ to deps", %{igniter: igniter} do
    igniter
    |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", @args)
    |> assert_has_patch("mix.exs", """
    + |      {:wax_, "~> 0.7"},
    """)
  end

  test "creates the credential resource", %{igniter: igniter} do
    igniter
    |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", @args)
    |> assert_creates("lib/test/accounts/web_authn_credential.ex")
  end

  test "credential resource has the WebAuthn-specific attributes", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", @args)

    diff = diff(result)
    assert diff =~ "credential_id"
    assert diff =~ "AshAuthentication.Strategy.WebAuthn.CoseKey"
    assert diff =~ "sign_count"
    assert diff =~ "label"
  end

  test "credential resource has a belongs_to user relationship", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", @args)

    assert diff(result) =~ "belongs_to :user"
  end

  test "credential resource has the AshAuthenticationInteraction policy bypass", %{
    igniter: igniter
  } do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", @args)

    assert diff(result) =~ "AshAuthentication.Checks.AshAuthenticationInteraction"
  end

  test "credential resource registers Ash.Policy.Authorizer", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", @args)

    assert diff(result) =~ "authorizers: [Ash.Policy.Authorizer]"
  end

  test "adds the has_many :webauthn_credentials relationship to the user", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", @args)

    assert diff(result) =~ "has_many(:webauthn_credentials, Test.Accounts.WebAuthnCredential)"
  end

  test "adds the WebAuthn strategy with rp_id, rp_name, identity_field", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", @args)

    diff = diff(result)
    assert diff =~ "webauthn :webauthn"
    assert diff =~ "rp_id(\"example.com\")"
    assert diff =~ "rp_name(\"Test App\")"
    assert diff =~ "identity_field(:email)"
  end

  test "honours --origin when supplied", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task(
        "ash_authentication.add_strategy.webauthn",
        @args ++ ["--origin", "https://localhost:4001"]
      )

    assert diff(result) =~ "origin(\"https://localhost:4001\")"
  end
end
