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

  # Regression test: `diff =~` string checks (as used elsewhere in this file)
  # can't tell a well-formed `webauthn_credential do ... end` block apart from
  # a corrupt `webauthn_credential(:user_resource)` call, or a `policies`
  # block that got spliced inside `attributes` instead of the top level.
  # Both shapes still contain the substrings the other tests assert on, but
  # only one of them actually compiles. Swap in an Ets-backed domain/user so
  # this doesn't need Postgres, then compile the real generated source
  # through the real `AshAuthentication.WebAuthnCredential` extension.
  test "the generated credential resource actually compiles", %{igniter: igniter} do
    result = Igniter.compose_task(igniter, "ash_authentication.add_strategy.webauthn", [])

    source =
      result.rewrite
      |> Rewrite.source!("lib/test/accounts/web_authn_credential.ex")
      |> Rewrite.Source.get(:content)

    module_name =
      Module.concat([
        "AshAuthentication.AddStrategy.WebauthnTest.Credential#{System.unique_integer([:positive])}"
      ])

    compilable_source =
      source
      |> String.replace("Test.Accounts.WebAuthnCredential", inspect(module_name))
      |> String.replace(
        "domain: Test.Accounts",
        "domain: AshAuthentication.Test.PermissiveDomain"
      )
      |> String.replace("data_layer: AshPostgres.DataLayer", "data_layer: Ash.DataLayer.Ets")
      |> String.replace(~r/postgres do.*?end\n/s, "ets do\n    private?(true)\n  end\n")
      |> String.replace("Test.Accounts.User", "Example.UserWithWebAuthn")
      |> String.replace(
        ~r/\nend\n\z/,
        """

          identities do
            identity :unique_credential_id, [:credential_id],
              pre_check_with: AshAuthentication.Test.PermissiveDomain
          end
        end
        """
      )

    compiled = Code.compile_string(compilable_source)

    assert {^module_name, _bytecode} = List.keyfind(compiled, module_name, 0)

    # The generated resource declares no `relationships` block — the
    # extension's transformer auto-builds `belongs_to :user`, reading the
    # foreign key's type off the real user resource's primary key. This
    # confirms the auto-built relationship actually exists post-compile
    # (not just that the file happens to compile).
    relationship = Ash.Resource.Info.relationship(module_name, :user)

    assert relationship,
           "expected a `:user` relationship to be auto-built on #{inspect(module_name)}, but none was found"

    assert %{
             type: :belongs_to,
             destination: Example.UserWithWebAuthn,
             allow_nil?: false,
             source_attribute: :user_id
           } = relationship
  end

  test "credential resource uses the AshAuthentication.WebAuthnCredential extension", %{
    igniter: igniter
  } do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    diff = diff(result)
    assert diff =~ "AshAuthentication.WebAuthnCredential"
    assert diff =~ "webauthn_credential"
    assert diff =~ "user_resource"
  end

  # Mirrors "when the user resource isn't named `User`, both generated
  # files agree on the relationship name" below — that test pins down the
  # `:account` override; this one pins down that the *default* `--user`
  # (`Test.Accounts.User`) still produces `:user` explicitly, not merely by
  # both independent DSL defaults happening to agree.
  test "with the default user resource, both generated files stamp `user_relationship_name(:user)`",
       %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    credential_diff = diff(result, only: "lib/test/accounts/web_authn_credential.ex")
    user_diff = diff(result, only: "lib/test/accounts/user.ex")

    assert credential_diff =~ "user_relationship_name(:user)"
    assert user_diff =~ "user_relationship_name(:user)"
  end

  # No explicit `relationships` block is generated — the extension's
  # transformer auto-builds `belongs_to :user` (see the "actually compiles"
  # test above for confirmation it's built correctly). Generating it
  # explicitly here would be redundant and, worse, would use Ash's generic
  # `default_belongs_to_type` config instead of the user resource's real
  # primary key type, so it could silently mismatch.
  test "credential resource does not declare an explicit relationships block", %{
    igniter: igniter
  } do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    refute diff(result, only: "lib/test/accounts/web_authn_credential.ex") =~ "relationships do"
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

    diff = diff(result, only: "lib/test/secrets.ex")
    assert diff =~ "[:authentication, :strategies, :webauthn, :rp_id]"
    assert diff =~ "[:authentication, :strategies, :webauthn, :rp_name]"
    assert diff =~ "[:authentication, :strategies, :webauthn, :origin]"
    assert diff =~ "Application.fetch_env(:test, :webauthn_rp_id)"
    assert diff =~ "Application.fetch_env(:test, :webauthn_rp_name)"
    assert diff =~ "Application.fetch_env(:test, :webauthn_origin)"
  end

  test "seeds dev.exs with sensible rp_id and rp_name defaults", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    diff = diff(result, only: "config/dev.exs")
    assert diff =~ "webauthn_rp_id: \"localhost\""
    assert diff =~ "webauthn_rp_name: \"Test\""
  end

  test "does not seed dev.exs `webauthn_origin` (it's resolved at runtime)", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    refute diff(result, only: "config/dev.exs") =~ "webauthn_origin"
  end

  test "seeds test.exs with sensible rp_id and rp_name defaults", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    diff = diff(result, only: "config/test.exs")
    assert diff =~ "webauthn_rp_id: \"localhost\""
    assert diff =~ "webauthn_rp_name: \"Test\""
  end

  test "does not seed test.exs `webauthn_origin` (it's resolved at runtime)", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    refute diff(result, only: "config/test.exs") =~ "webauthn_origin"
  end

  test "configures runtime.exs to read env vars in :prod", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    diff = diff(result, only: "config/runtime.exs")
    assert diff =~ ~s|webauthn_rp_id: System.get_env("WEBAUTHN_RP_ID")|
    assert diff =~ ~s|webauthn_rp_name: System.get_env("WEBAUTHN_RP_NAME")|
    assert diff =~ ~s|webauthn_origin: System.get_env("WEBAUTHN_ORIGIN")|
  end

  test "drops `allow_nil? false` from hashed_password when password is also installed",
       %{igniter: igniter} do
    igniter
    |> Igniter.compose_task("ash_authentication.add_strategy", ["password"])
    |> apply_igniter!()
    |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])
    |> assert_has_patch("lib/test/accounts/user.ex", """
      |    attribute :hashed_password, :string do
    - |      allow_nil?(false)
      |      sensitive?(true)
      |    end
    """)
  end

  test "in `--mode 2fa` disables registration and sign-in on the strategy", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", ["--mode", "2fa"])

    diff = diff(result, only: "lib/test/accounts/user.ex")
    assert diff =~ "webauthn :webauthn"
    assert diff =~ "registration_enabled?(false)"
    assert diff =~ "sign_in_enabled?(false)"
  end

  test "default mode (`primary`) leaves the new flags at their defaults", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    diff = diff(result, only: "lib/test/accounts/user.ex")
    refute diff =~ "registration_enabled?(false)"
    refute diff =~ "sign_in_enabled?(false)"
  end

  test "default mode emits `require_identity? true`", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])

    diff = diff(result, only: "lib/test/accounts/user.ex")
    assert diff =~ "require_identity?(true)"
    assert diff =~ "identity_field(:email)"
  end

  test "`--passkey-only` emits a no-identity strategy block", %{igniter: igniter} do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", ["--passkey-only"])

    diff = diff(result, only: "lib/test/accounts/user.ex")
    assert diff =~ "webauthn :webauthn"
    assert diff =~ "require_identity?(false)"
    refute diff =~ "identity_field"
  end

  test "`--passkey-only` does not add an identity attribute or identity to the user", %{
    igniter: igniter
  } do
    result =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", ["--passkey-only"])

    diff = diff(result, only: "lib/test/accounts/user.ex")
    refute diff =~ "attribute(:email"
    refute diff =~ "identity(:unique_email"
    assert diff =~ "has_many(:webauthn_credentials, Test.Accounts.WebAuthnCredential)"
  end

  test "is idempotent — running twice doesn't error or duplicate config", %{igniter: igniter} do
    igniter =
      igniter
      |> Igniter.compose_task("ash_authentication.add_strategy.webauthn", [])
      |> apply_igniter!()

    second_run = Igniter.compose_task(igniter, "ash_authentication.add_strategy.webauthn", [])

    assert second_run.issues == []

    refute diff(second_run, only: "lib/test/accounts/user.ex") =~ "webauthn :webauthn"
  end

  # `user_relationship_name` exists independently on both the credential
  # resource's `webauthn_credential` DSL and the user resource's `webauthn`
  # strategy DSL, and each has its own hardcoded `:user` default — they
  # can't agree with each other automatically at compile time. So when the
  # user resource isn't actually called `User`, the installer must compute
  # the relationship name once and stamp the *same* value into both
  # generated files, rather than relying on the two independent defaults to
  # happen to match (they only would if the user resource were named
  # `User`).
  test "when the user resource isn't named `User`, both generated files agree on the relationship name" do
    igniter =
      test_project()
      |> Igniter.Project.Deps.add_dep({:simple_sat, ">= 0.0.0"})
      |> Igniter.compose_task("ash_authentication.install", [
        "--yes",
        "--user",
        "Test.Accounts.Account",
        "--auth-strategy",
        "webauthn"
      ])

    assert igniter.issues == []

    credential_diff = diff(igniter, only: "lib/test/accounts/web_authn_credential.ex")
    account_diff = diff(igniter, only: "lib/test/accounts/account.ex")

    assert credential_diff =~ "user_relationship_name(:account)"
    assert account_diff =~ "user_relationship_name(:account)"
    refute credential_diff =~ "user_relationship_name(:user)"
    refute account_diff =~ "user_relationship_name(:user)"

    # The diff-text checks above only prove the *source* says
    # `user_relationship_name(:account)` — not that compiling it actually
    # produces a relationship named `:account` with an `:account_id`
    # foreign key. Compile the generated credential resource for real
    # (Ets instead of Postgres) against a minimal stand-in `Account`
    # resource — not the real generated `account.ex`, which also drags in
    # `Test.Accounts.Token`/`Test.Secrets` that aren't part of this bundle —
    # to close that gap, mirroring how "the generated credential resource
    # actually compiles" (above) isolates the credential resource using
    # `Example.UserWithWebAuthn` as its stand-in destination.
    credential_module =
      Module.concat([
        "AshAuthentication.AddStrategy.WebauthnTest.AccountCredential#{System.unique_integer([:positive])}"
      ])

    account_module =
      Module.concat([
        "AshAuthentication.AddStrategy.WebauthnTest.Account#{System.unique_integer([:positive])}"
      ])

    account_source = """
    defmodule #{inspect(account_module)} do
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets

      ets do
        private?(true)
      end

      attributes do
        uuid_primary_key(:id)
      end
    end
    """

    credential_source =
      igniter.rewrite
      |> Rewrite.source!("lib/test/accounts/web_authn_credential.ex")
      |> Rewrite.Source.get(:content)
      |> String.replace("Test.Accounts.WebAuthnCredential", inspect(credential_module))
      |> String.replace("Test.Accounts.Account", inspect(account_module))
      |> String.replace(
        "domain: Test.Accounts",
        "domain: AshAuthentication.Test.PermissiveDomain"
      )
      |> String.replace("data_layer: AshPostgres.DataLayer", "data_layer: Ash.DataLayer.Ets")
      |> String.replace(~r/postgres do.*?end\n/s, "ets do\n    private?(true)\n  end\n")
      |> String.replace(
        ~r/\nend\n\z/,
        """

          identities do
            identity :unique_credential_id, [:credential_id],
              pre_check_with: AshAuthentication.Test.PermissiveDomain
          end
        end
        """
      )

    Code.compile_string(account_source <> "\n" <> credential_source)

    relationship = Ash.Resource.Info.relationship(credential_module, :account)

    assert relationship,
           "expected a `:account` relationship on #{inspect(credential_module)} (the installer should " <>
             "have stamped `user_relationship_name :account` into the generated source), but none was found"

    assert %{
             type: :belongs_to,
             destination: ^account_module,
             source_attribute: :account_id
           } = relationship
  end
end
