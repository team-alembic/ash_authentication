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
      user_relationship_name <%= user_relationship_name %>
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

    test "register action accepts the register_action_accept fields" do
      actions = ResourceInfo.actions(Example.UserWithWebAuthn)
      action = Enum.find(actions, &(&1.name == :register_with_webauthn))
      assert :name in action.accept
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

    # The auto-built `has_many` used to hardcode `destination_attribute:
    # :user_id`, which silently pointed at a non-existent column for any user
    # resource not called `User`. It now leaves the attribute for Ash to
    # derive from the user resource's name, so assert the two ends actually
    # meet on the same column rather than just that the relationship exists.
    test "is auto-built pointing at the credential's own foreign key" do
      {user_module, credential_module} = compile_pair!()

      %{source_attribute: foreign_key} =
        ResourceInfo.relationships(credential_module)
        |> Enum.find(&(&1.type == :belongs_to))

      assert %{destination_attribute: ^foreign_key} =
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

    # The auto-built `has_many` derives its foreign key from the *user*
    # resource's name, so the credential's `belongs_to` has to be named after
    # that resource for the two ends to meet — the convention `BelongsTo`
    # defaults to for a resource called `User`, and the one the installer
    # stamps for any other name. These fixtures get a unique suffix per test
    # (`User1234`), so name the relationship explicitly to match, exactly as
    # the installer would.
    user_relationship_name = ":user#{suffix}"

    source =
      @user_source
      |> String.replace("<%= user_module %>", user_module_name)
      |> String.replace("<%= credential_module %>", credential_module_name)
      |> String.replace("<%= user_relationship_name %>", user_relationship_name)
      |> String.replace("<%= relationships %>", relationships)

    user_module = Module.concat([user_module_name])
    credential_module = Module.concat([credential_module_name])

    compiled = Code.compile_string(source)
    {^user_module, _bytecode} = List.keyfind(compiled, user_module, 0)
    {user_module, credential_module}
  end
end
