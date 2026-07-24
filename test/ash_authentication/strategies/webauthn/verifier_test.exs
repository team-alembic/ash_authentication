# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.VerifierTest do
  use ExUnit.Case, async: true

  import ExUnit.CaptureIO

  alias AshAuthentication.Strategy.WebAuthn.Verifier

  @moduletag feature: :webauthn

  @user_source """
  defmodule <%= user_module %> do
    @moduledoc false
    use Ash.Resource,
      domain: AshAuthentication.Test.PermissiveDomain,
      data_layer: Ash.DataLayer.Ets,
      extensions: [AshAuthentication]

    attributes do
      uuid_primary_key :id
    end

    ets do
      private?(true)
    end

    authentication do
      session_identifier(:jti)

      tokens do
        enabled? true
        token_resource Example.Token
        signing_secret &Example.User.get_config/2
      end

      strategies do
        webauthn :webauthn do
          credential_resource <%= credential_module %>
          rp_id "example.com"
          rp_name "Test App"
          origin "https://example.com"
          require_identity? false
        end
      end
    end
  end
  """

  describe "verify/2" do
    test "passes for valid configuration" do
      # Example.UserWithWebAuthn should compile without errors
      # The fact that it compiled means the verifier passed
      assert Example.UserWithWebAuthn.__info__(:module)
    end

    # As of 5.0 the credential resource must use the `WebAuthnCredential`
    # extension — the strategy reads every credential field name and the
    # belongs-to name off its DSL, and Spark would otherwise hand back this
    # extension's defaults for a resource that never declared them.
    test "rejects a credential resource that doesn't use the WebAuthnCredential extension" do
      output =
        capture_io(:stderr, fn ->
          compile_pair(
            credential_extensions: "",
            credential_body: """
              attributes do
                uuid_primary_key :id
              end
            """
          )
        end)

      assert output =~ "must use the `AshAuthentication.WebAuthnCredential` extension"
    end

    # The auto-built `has_many` derives its foreign key from the user
    # resource's name; the credential's `belongs_to` names its own. When the
    # two don't meet on the same column the relationship is silently broken,
    # so the verifier says so once the credential resource is compiled.
    test "rejects a credentials relationship that points at the wrong foreign key" do
      output =
        capture_io(:stderr, fn ->
          compile_pair(user_relationship_name: ":owner")
        end)

      assert output =~ "webauthn_credentials"
      assert output =~ "destination_attribute :owner_id"
    end
  end

  describe "manages_credentials_relationship?/2" do
    test "true when a change manages the given relationship" do
      action = %{
        changes: [
          %{
            change:
              {Ash.Resource.Change.ManageRelationship,
               argument: :webauthn_credentials, relationship: :webauthn_credentials, opts: []}
          }
        ]
      }

      assert Verifier.manages_credentials_relationship?(action, :webauthn_credentials)
    end

    test "false when no change manages the given relationship" do
      action = %{
        changes: [
          %{change: AshAuthentication.GenerateTokenChange}
        ]
      }

      refute Verifier.manages_credentials_relationship?(action, :webauthn_credentials)
    end

    test "false when a change manages a different relationship" do
      action = %{
        changes: [
          %{
            change:
              {Ash.Resource.Change.ManageRelationship,
               argument: :some_other_relationship,
               relationship: :some_other_relationship,
               opts: []}
          }
        ]
      }

      refute Verifier.manages_credentials_relationship?(action, :webauthn_credentials)
    end
  end

  # Compiles a throwaway credential resource, then a throwaway user resource
  # carrying a `webauthn` strategy that points at it.
  #
  # The two are compiled in separate passes, in that order, for two reasons
  # that pull against each other: the credential's transformer reads the user
  # resource's primary key, so it needs *a* compiled user resource (hence the
  # already-compiled `Example.UserWithWebAuthn` stand-in as its
  # `user_resource`); and the strategy verifier skips every credential check
  # when the credential module isn't loaded yet, so it has to be compiled
  # first for these tests to exercise anything at all.
  #
  # Strategy verifier failures run from `@after_verify`, so the parallel
  # checker reports them on stderr rather than raising out of
  # `Code.compile_string/1` — hence `capture_io(:stderr, ...)` at the call
  # sites instead of `assert_raise`.
  defp compile_pair(opts) do
    suffix = System.unique_integer([:positive])
    user_module = "AshAuthentication.Strategy.WebAuthn.VerifierTest.User#{suffix}"
    credential_module = "AshAuthentication.Strategy.WebAuthn.VerifierTest.Credential#{suffix}"

    # Defaults describe a *valid* pair, so each test overrides only the one
    # thing it is about. `:user#{suffix}` matches the foreign key Ash derives
    # for the generated `has_many` from the user resource's own name.
    extensions =
      Keyword.get(
        opts,
        :credential_extensions,
        ",\n    extensions: [AshAuthentication.WebAuthnCredential]"
      )

    relationship_name = Keyword.get(opts, :user_relationship_name, ":user#{suffix}")

    body =
      Keyword.get(opts, :credential_body, """
        webauthn_credential do
          user_resource Example.UserWithWebAuthn
          user_relationship_name #{relationship_name}
        end
      """)

    Code.compile_string("""
    defmodule #{credential_module} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets#{extensions}

      ets do
        private?(true)
      end

    #{body}
    end
    """)

    @user_source
    |> String.replace("<%= user_module %>", user_module)
    |> String.replace("<%= credential_module %>", credential_module)
    |> Code.compile_string()
  end
end
