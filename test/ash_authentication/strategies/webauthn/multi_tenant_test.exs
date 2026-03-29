defmodule AshAuthentication.Strategy.WebAuthn.MultiTenantTest do
  use DataCase, async: false

  alias AshAuthentication.{Info, Strategy.WebAuthn.Helpers}

  describe "multi-tenant rp_id resolution" do
    test "resolves dynamic rp_id via MFA" do
      strategy = Info.strategy!(Example.MultiTenantUserWithWebAuthn, :webauthn)
      assert "acme.example.com" = Helpers.resolve_rp_id(strategy, "acme")
      assert "globex.example.com" = Helpers.resolve_rp_id(strategy, "globex")
    end

    test "resolves dynamic rp_name via MFA" do
      strategy = Info.strategy!(Example.MultiTenantUserWithWebAuthn, :webauthn)
      assert "acme App" = Helpers.resolve_rp_name(strategy, "acme")
    end

    test "wax_opts builds correct origin for tenant" do
      strategy = Info.strategy!(Example.MultiTenantUserWithWebAuthn, :webauthn)
      opts = Helpers.wax_opts(strategy, "acme")
      assert opts[:origin] == "https://acme.example.com"
      assert opts[:rp_id] == "acme.example.com"
    end
  end
end
