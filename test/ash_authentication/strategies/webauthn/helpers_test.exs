# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.HelpersTest do
  use ExUnit.Case, async: true

  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Strategy.WebAuthn.Helpers

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

      def secret_for([:authentication, :strategies, :several, :origin], _, _, _),
        do: {:ok, ["https://a.example.com", "https://b.example.com"]}

      def secret_for([:authentication, :strategies, :bad_origin, :origin], _, _, _),
        do: {:ok, :not_an_origin}

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

    test "resolve_origin accepts a list of origins from a Secret module" do
      strategy = %WebAuthn{name: :several, resource: __MODULE__, origin: {TestSecrets, []}}

      assert ["https://a.example.com", "https://b.example.com"] =
               Helpers.resolve_origin(strategy, nil)
    end

    test "resolve_origin raises when a Secret module returns something else" do
      strategy = %WebAuthn{name: :bad_origin, resource: __MODULE__, origin: {TestSecrets, []}}

      assert_raise RuntimeError, ~r/to return `\{:ok, binary\}`/, fn ->
        Helpers.resolve_origin(strategy, nil)
      end
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

  describe "resolve_origin/2" do
    test "returns nil when no origin is configured" do
      assert is_nil(Helpers.resolve_origin(%WebAuthn{origin: nil}, nil))
    end

    test "returns a configured string or list as is" do
      assert "https://example.com" =
               Helpers.resolve_origin(%WebAuthn{origin: "https://example.com"}, nil)

      assert ["https://a.example.com"] =
               Helpers.resolve_origin(%WebAuthn{origin: ["https://a.example.com"]}, nil)
    end

    test "calls a function or MFA with the tenant, which may return a list" do
      assert ["https://acme.example.com"] =
               Helpers.resolve_origin(
                 %WebAuthn{origin: fn t -> ["https://#{t}.example.com"] end},
                 "acme"
               )

      assert "https://acme.example.com" =
               Helpers.resolve_origin(
                 %WebAuthn{origin: {__MODULE__, :origin_for_tenant, []}},
                 "acme"
               )
    end
  end

  describe "challenge_timeout_seconds/1" do
    test "converts the DSL's milliseconds to whole seconds" do
      assert Helpers.challenge_timeout_seconds(%WebAuthn{timeout: 60_000}) == 60
    end

    test "rounds a sub-second remainder up, so the server outlives the browser dialog" do
      assert Helpers.challenge_timeout_seconds(%WebAuthn{timeout: 120_001}) == 121
    end
  end

  # Test helper functions for MFA resolution
  def rp_id_for_tenant(tenant), do: "#{tenant}.example.com"
  def rp_name_for_tenant(tenant), do: "#{String.capitalize(tenant)} App"
  def origin_for_tenant(tenant), do: "https://#{tenant}.example.com"
end
