# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.WebAuthn.TransformerTest do
  use ExUnit.Case, async: true

  alias Ash.Resource.Info, as: ResourceInfo
  alias Spark.Error.DslError

  @moduletag feature: :webauthn

  @user_source """
  defmodule <%= user_module %> do
    @moduledoc false
    use Ash.Resource,
      domain: AshAuthentication.Test.PermissiveDomain,
      data_layer: Ash.DataLayer.Ets,
      extensions: [AshAuthentication]

    attributes do
      uuid_primary_key :id
    end

    ets do
      private?(true)
    end

    authentication do
      session_identifier(:jti)

      tokens do
        enabled? true
        token_resource Example.Token
        signing_secret &Example.User.get_config/2
      end

      strategies do
        webauthn :webauthn do
          credential_resource <%= credential_module %>
          rp_id "example.com"
          rp_name "Test App"
          origin "https://example.com"
          require_identity? false
        end
      end
    end

    relationships do
      <%= relationships %>
    end
  end

  defmodule <%= credential_module %> do
    @moduledoc false
    use Ash.Resource,
      domain: AshAuthentication.Test.PermissiveDomain,
      data_layer: Ash.DataLayer.Ets,
      extensions: [AshAuthentication.WebAuthnCredential]

    def testing_identities, do: :ok

    ets do
      private?(true)
    end

    webauthn_credential do
      user_resource <%= user_module %>
    end
  end
  """

  describe "user resource action injection" do
    test "injects register_with_webauthn create action" do
      actions = ResourceInfo.actions(Example.UserWithWebAuthn)
      action = Enum.find(actions, &(&1.name == :register_with_webauthn))
      assert action
      assert action.type == :create
    end

    test "register action accepts the identity field" do
      actions = ResourceInfo.actions(Example.UserWithWebAuthn)
      action = Enum.find(actions, &(&1.name == :register_with_webauthn))
      assert :email in action.accept
    end

    test "register action manages the webauthn_credentials relationship" do
      actions = ResourceInfo.actions(Example.UserWithWebAuthn)
      action = Enum.find(actions, &(&1.name == :register_with_webauthn))

      assert Enum.any?(action.changes, fn
               %{change: {Ash.Resource.Change.ManageRelationship, opts}} ->
                 opts[:relationship] == :webauthn_credentials

               _ ->
                 false
             end)
    end

    test "injects sign_in_with_webauthn read action" do
      actions = ResourceInfo.actions(Example.UserWithWebAuthn)
      action = Enum.find(actions, &(&1.name == :sign_in_with_webauthn))
      assert action
      assert action.type == :read
    end
  end

  describe "credentials relationship" do
    test "is auto-built when omitted, matching the configured credential_resource" do
      {user_module, credential_module} = compile_pair!()

      assert %{type: :has_many, destination: ^credential_module} =
               ResourceInfo.relationship(user_module, :webauthn_credentials)
    end

    test "a manually-declared relationship pointing at the wrong resource still raises a friendly DslError" do
      error =
        assert_raise DslError, fn ->
          compile_pair!(relationships: "has_many :webauthn_credentials, Example.Token")
        end

      assert error.message =~ "webauthn_credentials"
      assert error.message =~ "has_many"
    end
  end

  # Compiles a fresh, throwaway `webauthn`-strategy user resource paired with
  # its credential resource from a string source fixture, so each test can
  # exercise `WebAuthn.Transformer`'s relationship auto-build end-to-end.
  defp compile_pair!(opts \\ []) do
    suffix = System.unique_integer([:positive])
    user_module_name = "AshAuthentication.Strategy.WebAuthn.TransformerTest.User#{suffix}"

    credential_module_name =
      "AshAuthentication.Strategy.WebAuthn.TransformerTest.Credential#{suffix}"

    relationships = Keyword.get(opts, :relationships, "")

    source =
      @user_source
      |> String.replace("<%= user_module %>", user_module_name)
      |> String.replace("<%= credential_module %>", credential_module_name)
      |> String.replace("<%= relationships %>", relationships)

    user_module = Module.concat([user_module_name])
    credential_module = Module.concat([credential_module_name])

    compiled = Code.compile_string(source)
    {^user_module, _bytecode} = List.keyfind(compiled, user_module, 0)
    {user_module, credential_module}
  end
end
