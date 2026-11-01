# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.OriginTest do
  use ExUnit.Case, async: true

  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Strategy.WebAuthn.Origin

  @moduletag feature: :webauthn

  defmodule Secrets do
    use AshAuthentication.Secret

    def secret_for([:authentication, :strategies, :one, :origin], _, _, _),
      do: {:ok, "https://one.example.com"}

    def secret_for([:authentication, :strategies, :many, :origin], _, _, _),
      do: {:ok, ["https://a.example.com", "https://b.example.com"]}

    def secret_for(_, _, _, _), do: :error
  end

  defp strategy(overrides) do
    struct!(%WebAuthn{name: :webauthn, resource: __MODULE__, rp_id: "example.com"}, overrides)
  end

  describe "policy/2" do
    test "derives from the rp_id when no origin is configured" do
      assert Origin.policy(strategy(origin: nil), nil) == %{rp_id: "example.com"}
    end

    test "resolves the rp_id per tenant" do
      strategy = strategy(origin: nil, rp_id: fn tenant -> "#{tenant}.example.com" end)
      assert Origin.policy(strategy, "acme") == %{rp_id: "acme.example.com"}
    end

    test "a configured string is a one-entry allowlist" do
      assert Origin.policy(strategy(origin: "https://app.example.com"), nil) ==
               %{allow: ["https://app.example.com"]}
    end

    test "a configured list is the allowlist" do
      origins = ["https://a.example.com", "https://b.example.com:4001"]
      assert Origin.policy(strategy(origin: origins), nil) == %{allow: origins}
    end

    test "a tenant function may return a string or a list" do
      assert Origin.policy(strategy(origin: fn t -> "https://#{t}.example.com" end), "acme") ==
               %{allow: ["https://acme.example.com"]}

      assert Origin.policy(strategy(origin: fn t -> ["https://#{t}.example.com"] end), "acme") ==
               %{allow: ["https://acme.example.com"]}
    end

    test "an MFA receives the tenant first" do
      strategy = strategy(origin: {__MODULE__, :origins_for, ["suffix"]})
      assert Origin.policy(strategy, "acme") == %{allow: ["https://acme-suffix.example.com"]}
    end

    test "a Secret may return a string or a list" do
      assert Origin.policy(strategy(name: :one, origin: {Secrets, []}), nil) ==
               %{allow: ["https://one.example.com"]}

      assert Origin.policy(strategy(name: :many, origin: {Secrets, []}), nil) ==
               %{allow: ["https://a.example.com", "https://b.example.com"]}
    end

    test "a Secret answering :error falls back to the rp_id policy" do
      assert Origin.policy(strategy(name: :unknown, origin: {Secrets, []}), nil) ==
               %{rp_id: "example.com"}
    end
  end

  describe "allowed?/2 with an allowlist" do
    @allow %{allow: ["https://a.example.com", "https://b.example.com:4001"]}

    test "accepts an exact match" do
      assert Origin.allowed?("https://a.example.com", @allow)
      assert Origin.allowed?("https://b.example.com:4001", @allow)
    end

    test "is exact: port, scheme and subdomains all count" do
      refute Origin.allowed?("https://a.example.com:4001", @allow)
      refute Origin.allowed?("https://b.example.com", @allow)
      refute Origin.allowed?("http://a.example.com", @allow)
      refute Origin.allowed?("https://www.a.example.com", @allow)
      refute Origin.allowed?("https://example.com", @allow)
    end

    test "reads the string-keyed form a JSON session store produces" do
      assert Origin.allowed?("https://a.example.com", %{"allow" => ["https://a.example.com"]})
      refute Origin.allowed?("https://evil.com", %{"allow" => ["https://a.example.com"]})
    end

    test "treats a bare origin or list as an allowlist" do
      assert Origin.allowed?("https://a.example.com", "https://a.example.com")
      refute Origin.allowed?("https://b.example.com", "https://a.example.com")
      assert Origin.allowed?("https://a.example.com", ["https://a.example.com"])
    end
  end

  describe "allowed?/2 derived from the rp_id" do
    @policy %{rp_id: "example.com"}

    test "accepts https on the rp_id itself, on any port" do
      assert Origin.allowed?("https://example.com", @policy)
      assert Origin.allowed?("https://example.com:4001", @policy)
      assert Origin.allowed?("https://example.com:443", @policy)
    end

    test "accepts https on any subdomain, on any port" do
      assert Origin.allowed?("https://app.example.com", @policy)
      assert Origin.allowed?("https://deep.app.example.com", @policy)
      assert Origin.allowed?("https://app.example.com:8443", @policy)
    end

    test "rejects http" do
      refute Origin.allowed?("http://example.com", @policy)
      refute Origin.allowed?("http://app.example.com", @policy)
    end

    test "rejects other hosts, including look-alikes" do
      refute Origin.allowed?("https://evil.com", @policy)
      refute Origin.allowed?("https://notexample.com", @policy)
      refute Origin.allowed?("https://example.com.evil.com", @policy)
      refute Origin.allowed?("https://example.co", @policy)
    end

    test "rejects anything that isn't a bare origin" do
      refute Origin.allowed?("https://example.com/path", @policy)
      refute Origin.allowed?("https://example.com?x=1", @policy)
      refute Origin.allowed?("https://user@example.com", @policy)
      refute Origin.allowed?("example.com", @policy)
      refute Origin.allowed?("ftp://example.com", @policy)
      refute Origin.allowed?("", @policy)
    end

    test "compares hosts case-insensitively" do
      assert Origin.allowed?("https://App.Example.COM", @policy)
      assert Origin.allowed?("https://app.example.com", %{rp_id: "Example.com"})
    end

    test "accepts http://localhost only when the rp_id is localhost" do
      assert Origin.allowed?("http://localhost", %{rp_id: "localhost"})
      assert Origin.allowed?("http://localhost:4000", %{rp_id: "localhost"})
      assert Origin.allowed?("https://localhost:4001", %{rp_id: "localhost"})
      assert Origin.allowed?("http://app.localhost:4000", %{rp_id: "localhost"})
      refute Origin.allowed?("http://localhost:4000", @policy)
      refute Origin.allowed?("http://127.0.0.1:4000", %{rp_id: "localhost"})
    end

    test "reads the string-keyed form a JSON session store produces" do
      assert Origin.allowed?("https://app.example.com", %{"rp_id" => "example.com"})
      refute Origin.allowed?("https://evil.com", %{"rp_id" => "example.com"})
    end
  end

  describe "allowed?/2 with no policy" do
    test "fails closed" do
      refute Origin.allowed?("https://example.com", nil)
      refute Origin.allowed?("https://example.com", %{})
      refute Origin.allowed?(nil, %{rp_id: "example.com"})
    end
  end

  describe "well_formed?/1" do
    test "accepts scheme, host and optional port" do
      assert Origin.well_formed?("https://example.com")
      assert Origin.well_formed?("https://app.example.com:4001")
      assert Origin.well_formed?("http://localhost:4000")
    end

    test "rejects paths, queries, credentials, other schemes and non-strings" do
      refute Origin.well_formed?("https://example.com/")
      refute Origin.well_formed?("https://example.com/auth")
      refute Origin.well_formed?("https://example.com?x")
      refute Origin.well_formed?("https://user:pw@example.com")
      refute Origin.well_formed?("example.com")
      refute Origin.well_formed?("wss://example.com")
      refute Origin.well_formed?(nil)
    end
  end

  def origins_for(tenant, suffix), do: ["https://#{tenant}-#{suffix}.example.com"]
end
