defmodule AshAuthentication.Strategy.WebAuthn.VerifierTest do
  use ExUnit.Case, async: true

  describe "verify/2" do
    test "passes for valid configuration" do
      # Example.UserWithWebAuthn should compile without errors
      # The fact that it compiled means the verifier passed
      assert Example.UserWithWebAuthn.__info__(:module)
    end
  end
end
