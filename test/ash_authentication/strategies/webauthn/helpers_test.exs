# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.HelpersTest do
  use ExUnit.Case, async: true

  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Strategy.WebAuthn.Helpers
  alias AshAuthentication.Test.WebAuthnFixtures

  @moduletag feature: :webauthn

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

  describe "Secret module resolution" do
    defmodule TestSecrets do
      use AshAuthentication.Secret

      def secret_for([:authentication, :strategies, :webauthn, :rp_id], _, _, _),
        do: {:ok, "secret.example.com"}

      def secret_for([:authentication, :strategies, :webauthn, :rp_name], _, _, _),
        do: {:ok, "Secret App"}

      def secret_for([:authentication, :strategies, :webauthn, :origin], _, _, _),
        do: {:ok, "https://secret.example.com:4001"}

      def secret_for(_, _, _, _), do: :error
    end

    test "resolve_rp_id reads from a Secret module" do
      strategy = %WebAuthn{name: :webauthn, resource: __MODULE__, rp_id: {TestSecrets, []}}
      assert "secret.example.com" = Helpers.resolve_rp_id(strategy, nil)
    end

    test "resolve_rp_name reads from a Secret module" do
      strategy = %WebAuthn{name: :webauthn, resource: __MODULE__, rp_name: {TestSecrets, []}}
      assert "Secret App" = Helpers.resolve_rp_name(strategy, nil)
    end

    test "resolve_origin reads from a Secret module" do
      strategy = %WebAuthn{name: :webauthn, resource: __MODULE__, origin: {TestSecrets, []}}
      assert "https://secret.example.com:4001" = Helpers.resolve_origin(strategy, nil)
    end

    test "resolve_origin returns nil when the Secret module returns `:error`" do
      strategy = %WebAuthn{name: :other, resource: __MODULE__, origin: {TestSecrets, []}}
      assert is_nil(Helpers.resolve_origin(strategy, nil))
    end

    test "raises when the Secret module returns `:error` for a required field" do
      strategy = %WebAuthn{name: :other, resource: __MODULE__, rp_id: {TestSecrets, []}}

      assert_raise RuntimeError, ~r/returned `:error`/, fn ->
        Helpers.resolve_rp_id(strategy, nil)
      end
    end
  end

  describe "wax_opts/3" do
    test "builds Wax options from strategy" do
      strategy = %WebAuthn{
        rp_id: WebAuthnFixtures.default_rp_id(),
        user_verification: "required",
        attestation: "none"
      }

      opts = Helpers.wax_opts(strategy, nil)
      assert opts[:origin] == WebAuthnFixtures.default_origin()
      assert opts[:rp_id] == WebAuthnFixtures.default_rp_id()
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

  # These four tests exhaustively cover every combination of
  # `opts[:origin]` being present/absent and `strategy.origin` being
  # configured/unconfigured, pinning down the exact precedence order:
  #
  #     opts[:origin]  >  strategy.origin  >  "https://#{rp_id}"
  #
  # Each origin value is distinct (opts vs. configured vs. rp_id-derived) so
  # a passing assertion can only mean the intended source won — there's no
  # way for the wrong precedence to accidentally produce the same value.
  describe "wax_opts/3 origin precedence" do
    setup do
      %{rp_id: WebAuthnFixtures.default_rp_id()}
    end

    test "opts[:origin] wins when both opts[:origin] and strategy.origin are set", %{
      rp_id: rp_id
    } do
      strategy = %WebAuthn{
        rp_id: rp_id,
        origin: "https://configured-origin.example:8443",
        user_verification: "preferred",
        attestation: "none"
      }

      opts = Helpers.wax_opts(strategy, nil, origin: "http://opts-origin.example:4001")
      assert opts[:origin] == "http://opts-origin.example:4001"
    end

    test "strategy.origin wins when opts[:origin] is not set", %{rp_id: rp_id} do
      strategy = %WebAuthn{
        rp_id: rp_id,
        origin: "https://configured-origin.example:8443",
        user_verification: "preferred",
        attestation: "none"
      }

      opts = Helpers.wax_opts(strategy, nil)
      assert opts[:origin] == "https://configured-origin.example:8443"
    end

    test "opts[:origin] is used when strategy.origin is not configured", %{rp_id: rp_id} do
      strategy = %WebAuthn{
        rp_id: rp_id,
        origin: nil,
        user_verification: "preferred",
        attestation: "none"
      }

      opts = Helpers.wax_opts(strategy, nil, origin: "http://opts-origin.example:4001")
      assert opts[:origin] == "http://opts-origin.example:4001"
    end

    test "falls back to https://rp_id when neither opts[:origin] nor strategy.origin is set", %{
      rp_id: rp_id
    } do
      strategy = %WebAuthn{
        rp_id: rp_id,
        origin: nil,
        user_verification: "preferred",
        attestation: "none"
      }

      assert Helpers.wax_opts(strategy, nil)[:origin] == "https://#{rp_id}"
    end
  end

  # Test helper functions for MFA resolution
  def rp_id_for_tenant(tenant), do: "#{tenant}.example.com"
  def rp_name_for_tenant(tenant), do: "#{String.capitalize(tenant)} App"
end
