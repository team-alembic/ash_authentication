defmodule AshAuthentication.Strategy.WebAuthn.HelpersTest do
  use ExUnit.Case, async: true

  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Strategy.WebAuthn.Helpers

  describe "resolve_rp_id/2" do
    test "returns static string directly" do
      strategy = %WebAuthn{rp_id: "example.com"}
      assert "example.com" = Helpers.resolve_rp_id(strategy, nil)
    end

    test "calls MFA tuple with tenant" do
      strategy = %WebAuthn{rp_id: {__MODULE__, :rp_id_for_tenant, []}}
      assert "tenant1.example.com" = Helpers.resolve_rp_id(strategy, "tenant1")
    end

    test "calls function with tenant" do
      strategy = %WebAuthn{rp_id: fn tenant -> "#{tenant}.example.com" end}
      assert "tenant2.example.com" = Helpers.resolve_rp_id(strategy, "tenant2")
    end
  end

  describe "resolve_rp_name/2" do
    test "returns static string directly" do
      strategy = %WebAuthn{rp_name: "My App"}
      assert "My App" = Helpers.resolve_rp_name(strategy, nil)
    end

    test "calls MFA tuple with tenant" do
      strategy = %WebAuthn{rp_name: {__MODULE__, :rp_name_for_tenant, []}}
      assert "Tenant1 App" = Helpers.resolve_rp_name(strategy, "tenant1")
    end
  end

  describe "wax_opts/2" do
    test "builds Wax options from strategy" do
      strategy = %WebAuthn{
        rp_id: "example.com",
        user_verification: "required",
        attestation: "none"
      }

      opts = Helpers.wax_opts(strategy, nil)
      assert opts[:origin] == "https://example.com"
      assert opts[:rp_id] == "example.com"
      assert opts[:user_verification] == "required"
      assert opts[:attestation] == "none"
    end

    test "resolves dynamic rp_id for tenant" do
      strategy = %WebAuthn{
        rp_id: {__MODULE__, :rp_id_for_tenant, []},
        user_verification: "preferred",
        attestation: "none"
      }

      opts = Helpers.wax_opts(strategy, "tenant1")
      assert opts[:origin] == "https://tenant1.example.com"
      assert opts[:rp_id] == "tenant1.example.com"
    end
  end

  # Test helper functions for MFA resolution
  def rp_id_for_tenant(tenant), do: "#{tenant}.example.com"
  def rp_name_for_tenant(tenant), do: "#{String.capitalize(tenant)} App"
end
