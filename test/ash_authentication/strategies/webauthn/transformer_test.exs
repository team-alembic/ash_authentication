defmodule AshAuthentication.Strategy.WebAuthn.TransformerTest do
  use ExUnit.Case, async: true

  describe "user resource action injection" do
    test "injects register_with_webauthn create action" do
      actions = Ash.Resource.Info.actions(Example.UserWithWebAuthn)
      action = Enum.find(actions, &(&1.name == :register_with_webauthn))
      assert action
      assert action.type == :create
    end

    test "register action accepts the identity field" do
      actions = Ash.Resource.Info.actions(Example.UserWithWebAuthn)
      action = Enum.find(actions, &(&1.name == :register_with_webauthn))
      assert :email in action.accept
    end

    test "injects sign_in_with_webauthn read action" do
      actions = Ash.Resource.Info.actions(Example.UserWithWebAuthn)
      action = Enum.find(actions, &(&1.name == :sign_in_with_webauthn))
      assert action
      assert action.type == :read
    end
  end
end
