# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.VerifierTest do
  use ExUnit.Case, async: true

  alias AshAuthentication.Strategy.WebAuthn.Verifier

  @moduletag feature: :webauthn

  describe "verify/2" do
    test "passes for valid configuration" do
      # Example.UserWithWebAuthn should compile without errors
      # The fact that it compiled means the verifier passed
      assert Example.UserWithWebAuthn.__info__(:module)
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
end
