# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.RelyingPartyConfigurationsTest do
  @moduledoc """
  Ceremonies under the relying-party configurations the DSL accepts, run
  end to end against challenges the strategy issues itself:

  - **Multi-tenant:** `rp_id`/`origin` as an MFA of the tenant and `rp_name`
    as a function of it, on resources with attribute multitenancy.
  - **Secret module:** `rp_id`, `rp_name` and `origin` read from an
    `AshAuthentication.Secret` module.
  - **Secret module, per tenant:** a Secret that reads the tenant from its
    context, on resources with attribute multitenancy: one shared `rp_id`
    (the apex domain) and each tenant's own exact `origin`.
  - **Passkey-first + verify:** the second-factor ceremony on a strategy
    whose users have no identity.

  It also checks the creation and request options sent to the browser for
  every `resident_key` and `user_verification` value.
  """
  use DataCase, async: false

  import Plug.Test

  alias AshAuthentication.Errors.AuthenticationFailed
  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.WebAuthn
  alias AshAuthentication.Strategy.WebAuthn.Actions
  alias AshAuthentication.Test.WebAuthnCeremony

  @moduletag feature: :webauthn

  setup_all do
    suffix = System.unique_integer([:positive])
    base = "AshAuthentication.Strategy.WebAuthn.RelyingPartyConfigurationsTest"

    tenant_user = "#{base}.TenantUser#{suffix}"
    tenant_credential = "#{base}.TenantCredential#{suffix}"
    secret_user = "#{base}.SecretUser#{suffix}"
    secret_credential = "#{base}.SecretCredential#{suffix}"
    secrets = "#{base}.Secrets#{suffix}"
    tenant_secrets = "#{base}.TenantSecrets#{suffix}"
    tenant_secret_user = "#{base}.TenantSecretUser#{suffix}"
    tenant_secret_credential = "#{base}.TenantSecretCredential#{suffix}"

    # Each user resource is compiled before its credential resource: the
    # credential extension reads the user's primary key.
    Code.compile_string("""
    defmodule #{tenant_user} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication]

      ets do
        private?(true)
      end

      multitenancy do
        strategy :attribute
        attribute :org
      end

      attributes do
        uuid_primary_key :id
        attribute :org, :string, allow_nil?: false, public?: true
      end

      actions do
        defaults [:read]
      end

      relationships do
        has_many :webauthn_credentials, #{tenant_credential},
          destination_attribute: :tenant_user#{suffix}_id
      end

      authentication do
        session_identifier(:jti)

        tokens do
          enabled? true
          store_all_tokens? true
          token_resource Example.Token
          signing_secret &Example.User.get_config/2
        end

        strategies do
          webauthn :webauthn do
            credential_resource #{tenant_credential}
            require_identity? false
            rp_id {__MODULE__, :rp_id_for, []}
            rp_name fn tenant -> "\#{tenant} App" end
            origin {__MODULE__, :origin_for, []}
          end
        end
      end

      def rp_id_for(tenant), do: "\#{tenant}.example.com"
      def origin_for(tenant), do: "https://\#{tenant}.example.com"
    end

    defmodule #{tenant_credential} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication.WebAuthnCredential]

      ets do
        private?(true)
      end

      multitenancy do
        strategy :attribute
        attribute :org
      end

      attributes do
        attribute :org, :string, allow_nil?: false, public?: true
      end

      webauthn_credential do
        user_resource #{tenant_user}
        user_relationship_name :tenant_user#{suffix}
      end
    end
    """)

    Code.compile_string("""
    defmodule #{secrets} do
      @moduledoc false
      use AshAuthentication.Secret

      def secret_for([:authentication, :strategies, :webauthn, :rp_id], _, _, _),
        do: {:ok, "secret.example.com"}

      def secret_for([:authentication, :strategies, :webauthn, :rp_name], _, _, _),
        do: {:ok, "Secret App"}

      def secret_for([:authentication, :strategies, :webauthn, :origin], _, _, _),
        do: {:ok, "https://login.secret.example.com"}

      def secret_for(_, _, _, _), do: :error
    end

    defmodule #{secret_user} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication]

      ets do
        private?(true)
      end

      attributes do
        uuid_primary_key :id
      end

      actions do
        defaults [:read]
      end

      relationships do
        has_many :webauthn_credentials, #{secret_credential},
          destination_attribute: :secret_user#{suffix}_id
      end

      authentication do
        session_identifier(:jti)

        tokens do
          enabled? true
          store_all_tokens? true
          token_resource Example.Token
          signing_secret &Example.User.get_config/2
        end

        strategies do
          webauthn :webauthn do
            credential_resource #{secret_credential}
            require_identity? false
            rp_id #{secrets}
            rp_name #{secrets}
            origin #{secrets}
          end
        end
      end
    end

    defmodule #{secret_credential} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication.WebAuthnCredential]

      ets do
        private?(true)
      end

      webauthn_credential do
        user_resource #{secret_user}
        user_relationship_name :secret_user#{suffix}
      end
    end
    """)

    # The Secret never sees the request's tenant as an argument; it comes in
    # the context the strategy hands over. Tenants are subdomains of one
    # apex, so they share its rp_id and differ in origin.
    Code.compile_string("""
    defmodule #{tenant_secrets} do
      @moduledoc false
      use AshAuthentication.Secret

      def secret_for([:authentication, :strategies, :webauthn, :rp_id], _, _, _),
        do: {:ok, "example.com"}

      def secret_for([:authentication, :strategies, :webauthn, :rp_name], _, _, %{tenant: tenant}),
        do: {:ok, "\#{tenant} App"}

      def secret_for([:authentication, :strategies, :webauthn, :origin], _, _, %{tenant: tenant}),
        do: {:ok, "https://\#{tenant}.example.com"}

      def secret_for(_, _, _, _), do: :error
    end

    defmodule #{tenant_secret_user} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication]

      ets do
        private?(true)
      end

      multitenancy do
        strategy :attribute
        attribute :org
      end

      attributes do
        uuid_primary_key :id
        attribute :org, :string, allow_nil?: false, public?: true
      end

      actions do
        defaults [:read]
      end

      relationships do
        has_many :webauthn_credentials, #{tenant_secret_credential},
          destination_attribute: :tenant_secret_user#{suffix}_id
      end

      authentication do
        session_identifier(:jti)

        tokens do
          enabled? true
          store_all_tokens? true
          token_resource Example.Token
          signing_secret &Example.User.get_config/2
        end

        strategies do
          webauthn :webauthn do
            credential_resource #{tenant_secret_credential}
            require_identity? false
            rp_id #{tenant_secrets}
            rp_name #{tenant_secrets}
            origin #{tenant_secrets}
          end
        end
      end
    end

    defmodule #{tenant_secret_credential} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication.WebAuthnCredential]

      ets do
        private?(true)
      end

      multitenancy do
        strategy :attribute
        attribute :org
      end

      attributes do
        attribute :org, :string, allow_nil?: false, public?: true
      end

      webauthn_credential do
        user_resource #{tenant_secret_user}
        user_relationship_name :tenant_secret_user#{suffix}
      end
    end
    """)

    %{
      tenanted: Info.strategy!(Module.concat([tenant_user]), :webauthn),
      secret: Info.strategy!(Module.concat([secret_user]), :webauthn),
      tenant_secret: Info.strategy!(Module.concat([tenant_secret_user]), :webauthn)
    }
  end

  describe "multi-tenant relying party" do
    test "the relying party is resolved per tenant", ctx do
      assert WebAuthnCeremony.relying_party(ctx.tenanted, "acme") ==
               {"acme.example.com", "https://acme.example.com"}

      body = registration_options(ctx.tenanted, tenant: "globex")
      assert body["rp"] == %{"id" => "globex.example.com", "name" => "globex App"}
    end

    test "a user registers and signs in within their tenant", ctx do
      {{:ok, user}, passkey} = WebAuthnCeremony.register(ctx.tenanted, %{}, tenant: "acme")
      assert user.org == "acme"

      assert {:ok, signed_in} =
               WebAuthnCeremony.sign_in(ctx.tenanted, passkey, %{}, tenant: "acme")

      assert signed_in.id == user.id

      assert {:ok, [credential]} = Actions.list_credentials(ctx.tenanted, user, tenant: "acme")
      assert credential.org == "acme"
    end

    test "a credential doesn't exist in another tenant", ctx do
      {{:ok, _user}, passkey} = WebAuthnCeremony.register(ctx.tenanted, %{}, tenant: "acme")

      # A well-formed assertion for globex's relying party, with acme's passkey.
      assert {:error, %AuthenticationFailed{}} =
               WebAuthnCeremony.sign_in(ctx.tenanted, passkey, %{}, tenant: "globex")
    end

    test "an assertion for another tenant's relying party is rejected", ctx do
      {{:ok, _user}, passkey} = WebAuthnCeremony.register(ctx.tenanted, %{}, tenant: "acme")

      assert {:error, %AuthenticationFailed{}} =
               WebAuthnCeremony.sign_in(ctx.tenanted, passkey, %{},
                 tenant: "acme",
                 rp_id: "globex.example.com",
                 origin: "https://globex.example.com"
               )
    end

    test "second-factor verification is scoped to the tenant", ctx do
      {{:ok, user}, passkey} = WebAuthnCeremony.register(ctx.tenanted, %{}, tenant: "acme")

      assert {:ok, verified} =
               WebAuthnCeremony.verify(ctx.tenanted, user, passkey, tenant: "acme")

      assert %DateTime{} = verified.__metadata__.webauthn_verified_at
    end
  end

  describe "relying party from a Secret module" do
    test "rp_id, rp_name and origin are read from the module", ctx do
      assert WebAuthnCeremony.relying_party(ctx.secret) ==
               {"secret.example.com", "https://login.secret.example.com"}

      assert registration_options(ctx.secret)["rp"] == %{
               "id" => "secret.example.com",
               "name" => "Secret App"
             }
    end

    test "a user registers and signs in against it", ctx do
      {{:ok, user}, passkey} = WebAuthnCeremony.register(ctx.secret)
      assert {:ok, signed_in} = WebAuthnCeremony.sign_in(ctx.secret, passkey)
      assert signed_in.id == user.id
    end
  end

  describe "relying party from a Secret module, per tenant" do
    test "the Secret reads the tenant from its context", ctx do
      assert WebAuthnCeremony.relying_party(ctx.tenant_secret, "acme") ==
               {"example.com", "https://acme.example.com"}

      assert WebAuthnCeremony.relying_party(ctx.tenant_secret, "globex") ==
               {"example.com", "https://globex.example.com"}

      body = registration_options(ctx.tenant_secret, tenant: "globex")
      assert body["rp"] == %{"id" => "example.com", "name" => "globex App"}
    end

    test "the challenge carries the tenant's origin as an exact allowlist", ctx do
      {:ok, challenge} = Actions.registration_challenge(ctx.tenant_secret, "acme")

      assert challenge.rp_id == "example.com"
      assert challenge.origin == %{allow: ["https://acme.example.com"]}
    end

    test "a user registers and signs in within their tenant", ctx do
      {{:ok, user}, passkey} = WebAuthnCeremony.register(ctx.tenant_secret, %{}, tenant: "acme")
      assert user.org == "acme"

      assert {:ok, signed_in} =
               WebAuthnCeremony.sign_in(ctx.tenant_secret, passkey, %{}, tenant: "acme")

      assert signed_in.id == user.id
    end

    test "an assertion from another tenant's origin is rejected, same rp_id or not", ctx do
      {{:ok, _user}, passkey} = WebAuthnCeremony.register(ctx.tenant_secret, %{}, tenant: "acme")

      assert {:error, %AuthenticationFailed{}} =
               WebAuthnCeremony.sign_in(ctx.tenant_secret, passkey, %{},
                 tenant: "acme",
                 origin: "https://globex.example.com"
               )
    end

    test "a credential doesn't exist in another tenant", ctx do
      {{:ok, _user}, passkey} = WebAuthnCeremony.register(ctx.tenant_secret, %{}, tenant: "acme")

      assert {:error, %AuthenticationFailed{}} =
               WebAuthnCeremony.sign_in(ctx.tenant_secret, passkey, %{}, tenant: "globex")
    end
  end

  describe "passkey-first with second-factor verification" do
    test "a user with no identity verifies with their passkey" do
      strategy = Info.strategy!(Example.UserWithWebAuthnNoIdentity, :webauthn)
      {{:ok, user}, passkey} = WebAuthnCeremony.register(strategy)

      assert {:ok, verified} = WebAuthnCeremony.verify(strategy, user, passkey)
      assert verified.id == user.id
      assert %DateTime{} = verified.__metadata__.webauthn_verified_at
    end

    test "and can't verify with someone else's passkey" do
      strategy = Info.strategy!(Example.UserWithWebAuthnNoIdentity, :webauthn)
      {{:ok, user}, _passkey} = WebAuthnCeremony.register(strategy)
      {{:ok, _other}, other_passkey} = WebAuthnCeremony.register(strategy)

      assert {:error, %AuthenticationFailed{}} =
               WebAuthnCeremony.verify(strategy, user, other_passkey)
    end
  end

  describe "options sent to the browser" do
    setup do
      %{strategy: Info.strategy!(Example.UserWithWebAuthn, :webauthn)}
    end

    for {resident_key, required?} <- [required: true, preferred: false, discouraged: false] do
      test "resident_key #{inspect(resident_key)}", %{strategy: strategy} do
        selection =
          %{strategy | resident_key: unquote(resident_key)}
          |> registration_options()
          |> Map.fetch!("authenticatorSelection")

        assert selection["residentKey"] == to_string(unquote(resident_key))
        assert selection["requireResidentKey"] == unquote(required?)
      end
    end

    for user_verification <- ["required", "preferred", "discouraged"] do
      test "user_verification #{inspect(user_verification)}", %{strategy: strategy} do
        strategy = %{strategy | user_verification: unquote(user_verification)}

        assert registration_options(strategy)["authenticatorSelection"]["userVerification"] ==
                 unquote(user_verification)

        assert authentication_options(strategy)["userVerification"] ==
                 unquote(user_verification)
      end
    end

    test "attestation and timeout", %{strategy: strategy} do
      strategy = %{strategy | attestation: "direct", timeout: 180_000}

      assert registration_options(strategy)["attestation"] == "direct"
      assert registration_options(strategy)["timeout"] == 180_000
      assert authentication_options(strategy)["timeout"] == 180_000
    end
  end

  defp registration_options(strategy, opts \\ []) do
    :get
    |> conn("https://example.com/registration_challenge", %{})
    |> SessionPipeline.call([])
    |> maybe_set_tenant(opts[:tenant])
    |> WebAuthn.Plug.registration_challenge(strategy)
    |> Map.fetch!(:resp_body)
    |> Jason.decode!()
  end

  defp authentication_options(strategy) do
    :get
    |> conn("https://example.com/authentication_challenge", %{})
    |> SessionPipeline.call([])
    |> WebAuthn.Plug.authentication_challenge(strategy)
    |> Map.fetch!(:resp_body)
    |> Jason.decode!()
  end

  defp maybe_set_tenant(conn, nil), do: conn
  defp maybe_set_tenant(conn, tenant), do: Ash.PlugHelpers.set_tenant(conn, tenant)
end
