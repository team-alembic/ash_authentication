# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.CredentialLabelTest do
  @moduledoc """
  The label an unnamed passkey gets is the credential resource's, not the
  strategy's. The extension's `label` attribute defaults to `"Security Key"`
  on a resource that doesn't declare one; a resource that declares `label`
  itself decides, and may leave it `nil` for a UI that translates the
  fallback.
  """
  use DataCase, async: false

  alias AshAuthentication.Info
  alias AshAuthentication.Strategy.WebAuthn.Actions
  alias AshAuthentication.Test.WebAuthnCeremony

  @moduletag feature: :webauthn

  setup_all do
    suffix = System.unique_integer([:positive])
    base = "AshAuthentication.Strategy.WebAuthn.CredentialLabelTest"
    user = "#{base}.User#{suffix}"
    credential = "#{base}.Credential#{suffix}"

    Code.compile_string("""
    defmodule #{user} do
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
        has_many :webauthn_credentials, #{credential},
          destination_attribute: :user#{suffix}_id
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
            credential_resource #{credential}
            require_identity? false
            rp_id "example.com"
            rp_name "Test App"
            origin "https://example.com"
          end
        end
      end
    end

    defmodule #{credential} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication.WebAuthnCredential]

      ets do
        private?(true)
      end

      # Declared by the resource, with no default: an unnamed passkey has no
      # label, and the UI shows its own, translated, fallback.
      attributes do
        attribute :label, :string, public?: true
      end

      webauthn_credential do
        user_resource #{user}
        user_relationship_name :user#{suffix}
      end
    end
    """)

    %{
      no_default: Info.strategy!(Module.concat([user]), :webauthn),
      stock: Info.strategy!(Example.UserWithWebAuthnNoIdentity, :webauthn)
    }
  end

  describe "a credential resource that declares label with no default" do
    test "an unnamed passkey registers with no label", ctx do
      {{:ok, user}, _passkey} = WebAuthnCeremony.register(ctx.no_default)
      assert [%{label: nil}] = credentials(ctx.no_default, user)
    end

    test "a blank name counts as none", ctx do
      {{:ok, user}, _passkey} = WebAuthnCeremony.register(ctx.no_default, %{"label" => ""})
      assert [%{label: nil}] = credentials(ctx.no_default, user)
    end

    test "an unnamed passkey added later has no label either", ctx do
      {{:ok, user}, _passkey} = WebAuthnCeremony.register(ctx.no_default, %{"label" => "First"})
      {{:ok, added}, _passkey} = WebAuthnCeremony.add_credential(ctx.no_default, user)

      assert is_nil(added.label)

      # The credential resource has no create timestamp, so the list comes in
      # the data layer's order.
      assert ctx.no_default |> credentials(user) |> Enum.map(& &1.label) |> Enum.sort() ==
               [nil, "First"]
    end

    test "a given name is stored as given", ctx do
      {{:ok, user}, _passkey} =
        WebAuthnCeremony.register(ctx.no_default, %{"label" => "Work laptop"})

      assert [%{label: "Work laptop"}] = credentials(ctx.no_default, user)
    end
  end

  describe "a credential resource that leaves label to the extension" do
    test "an unnamed passkey is still a \"Security Key\", registered or added", ctx do
      {{:ok, user}, _passkey} = WebAuthnCeremony.register(ctx.stock)
      {{:ok, added}, _passkey} = WebAuthnCeremony.add_credential(ctx.stock, user)

      assert added.label == "Security Key"
      assert [%{label: "Security Key"}, %{label: "Security Key"}] = credentials(ctx.stock, user)
    end

    test "a given name is stored as given", ctx do
      {{:ok, user}, _passkey} = WebAuthnCeremony.register(ctx.stock, %{"label" => "Phone"})
      assert [%{label: "Phone"}] = credentials(ctx.stock, user)
    end
  end

  defp credentials(strategy, user) do
    {:ok, credentials} = Actions.list_credentials(strategy, user, [])
    credentials
  end
end
