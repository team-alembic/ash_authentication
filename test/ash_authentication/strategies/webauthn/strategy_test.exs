defmodule AshAuthentication.Strategy.WebAuthn.StrategyTest do
  use ExUnit.Case, async: true

  alias AshAuthentication.Strategy
  alias AshAuthentication.Strategy.WebAuthn

  setup do
    strategy = %WebAuthn{
      name: :webauthn,
      resource: Example.User,
      credential_resource: Example.WebAuthnCredential,
      rp_id: "example.com",
      rp_name: "My App",
      identity_field: :email,
      registration_enabled?: true,
      register_action_name: :register_with_webauthn,
      sign_in_action_name: :sign_in_with_webauthn,
      store_credential_action_name: :store_webauthn_credential,
      update_sign_count_action_name: :update_webauthn_sign_count,
      list_credentials_action_name: :list_webauthn_credentials,
      delete_credential_action_name: :delete_webauthn_credential,
      update_credential_label_action_name: :update_webauthn_credential_label,
      add_credential_action_name: :add_webauthn_credential
    }

    %{strategy: strategy}
  end

  describe "name/1" do
    test "returns the strategy name", %{strategy: strategy} do
      assert :webauthn = Strategy.name(strategy)
    end
  end

  describe "phases/1" do
    test "returns all four phases when registration enabled", %{strategy: strategy} do
      phases = Strategy.phases(strategy)
      assert :registration_challenge in phases
      assert :register in phases
      assert :authentication_challenge in phases
      assert :sign_in in phases
    end

    test "excludes registration phases when registration disabled" do
      strategy = %WebAuthn{
        name: :webauthn,
        resource: Example.User,
        registration_enabled?: false,
        sign_in_action_name: :sign_in_with_webauthn
      }

      phases = Strategy.phases(strategy)
      refute :registration_challenge in phases
      refute :register in phases
      assert :authentication_challenge in phases
      assert :sign_in in phases
    end
  end

  describe "actions/1" do
    test "returns register and sign_in", %{strategy: strategy} do
      actions = Strategy.actions(strategy)
      assert :register in actions
      assert :sign_in in actions
    end
  end

  describe "routes/1" do
    test "returns routes for all phases", %{strategy: strategy} do
      routes = Strategy.routes(strategy)
      paths = Enum.map(routes, &elem(&1, 0))

      assert Enum.any?(paths, &String.contains?(&1, "registration_challenge"))
      assert Enum.any?(paths, &String.contains?(&1, "register"))
      assert Enum.any?(paths, &String.contains?(&1, "authentication_challenge"))
      assert Enum.any?(paths, &String.contains?(&1, "sign_in"))
    end
  end

  describe "method_for_phase/2" do
    test "challenge phases use GET", %{strategy: strategy} do
      assert :get = Strategy.method_for_phase(strategy, :registration_challenge)
      assert :get = Strategy.method_for_phase(strategy, :authentication_challenge)
    end

    test "action phases use POST", %{strategy: strategy} do
      assert :post = Strategy.method_for_phase(strategy, :register)
      assert :post = Strategy.method_for_phase(strategy, :sign_in)
    end
  end

  describe "tokens_required?/1" do
    test "returns true", %{strategy: strategy} do
      assert Strategy.tokens_required?(strategy)
    end
  end
end
