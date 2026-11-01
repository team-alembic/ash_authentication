# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.MultiTenantTest do
  use DataCase, async: false

  alias AshAuthentication.{Info, Strategy.WebAuthn.Actions, Strategy.WebAuthn.Helpers}

  @moduletag feature: :webauthn

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

    test "the challenge carries the tenant's relying party" do
      strategy = Info.strategy!(Example.MultiTenantUserWithWebAuthn, :webauthn)
      {:ok, challenge} = Actions.registration_challenge(strategy, "acme")
      assert challenge.rp_id == "acme.example.com"
      assert challenge.origin == "https://acme.example.com"
    end
  end
end
