# SPDX-FileCopyrightText: 2026 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.WebAuthnCredential.VerifierTest do
  use ExUnit.Case, async: true

  alias Ash.Resource.Info, as: ResourceInfo

  @moduletag feature: :webauthn

  @credential_source """
  defmodule <%= module %> do
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
      user_resource(Example.UserWithWebAuthn)
    end

    relationships do
      <%= relationships %>
    end
  end
  """

  describe "belongs_to relationship" do
    test "is auto-built when omitted, matching the configured user_resource" do
      module = compile_credential!()
      relationship = ResourceInfo.relationship(module, :user)

      assert relationship,
             "expected a `:user` relationship to be auto-built on #{inspect(module)}, but none was found"

      assert %{
               type: :belongs_to,
               destination: Example.UserWithWebAuthn,
               allow_nil?: false,
               source_attribute: :user_id
             } = relationship
    end

    test "a manually-declared belongs_to pointing at the wrong resource still raises a friendly DslError" do
      error =
        assert_raise Spark.Error.DslError, fn ->
          compile_credential!(relationships: "belongs_to :user, Example.Token")
        end

      assert error.message =~ "user"
      assert error.message =~ "#{inspect(Example.UserWithWebAuthn)}"
    end

    # The foreign key is named after `user_id_field` (default `:user_id`),
    # not derived from the `user_resource` module's own name — so a
    # `user_resource` called `Account` (rather than `User`) must still end
    # up with a `:user_id` foreign key, not `:account_id`.
    test "the foreign key stays `:user_id` even when `user_resource` isn't named `User`" do
      account_module_name =
        "AshAuthentication.WebAuthnCredential.VerifierTest.Account#{System.unique_integer([:positive])}"

      credential_module_name =
        "AshAuthentication.WebAuthnCredential.VerifierTest.Credential#{System.unique_integer([:positive])}"

      account_source = """
      defmodule #{account_module_name} do
        @moduledoc false
        use Ash.Resource,
          domain: AshAuthentication.Test.PermissiveDomain,
          data_layer: Ash.DataLayer.Ets

        ets do
          private?(true)
        end

        attributes do
          uuid_primary_key(:id)
        end
      end
      """

      credential_source = """
      defmodule #{credential_module_name} do
        @moduledoc false
        use Ash.Resource,
          domain: AshAuthentication.Test.PermissiveDomain,
          data_layer: Ash.DataLayer.Ets,
          extensions: [AshAuthentication.WebAuthnCredential]

        ets do
          private?(true)
        end

        webauthn_credential do
          user_resource(#{account_module_name})
        end

        identities do
          identity :unique_credential_id, [:credential_id],
            pre_check_with: AshAuthentication.Test.PermissiveDomain
        end
      end
      """

      account_module = Module.concat([account_module_name])
      credential_module = Module.concat([credential_module_name])

      compiled = Code.compile_string(account_source <> "\n" <> credential_source)
      {^credential_module, _bytecode} = List.keyfind(compiled, credential_module, 0)

      relationship = ResourceInfo.relationship(credential_module, :user)

      assert relationship,
             "expected the default `:user` relationship to still exist on #{inspect(credential_module)} " <>
               "even though its user_resource (#{inspect(account_module)}) isn't named `User` — " <>
               "`user_relationship_name` wasn't configured, so it should not have moved"

      assert %{
               type: :belongs_to,
               destination: ^account_module,
               source_attribute: :user_id,
               destination_attribute: :id
             } = relationship
    end

    # `user_id_field` defaults to `nil`, so leaving it unset lets
    # `Ash.Resource.Relationships.BelongsTo`'s own `<name>_id` convention
    # apply to whatever `user_relationship_name` actually is — so
    # configuring the relationship as `:account` (e.g. because the real
    # `user_resource` is called `Account`) gets an `:account_id` foreign
    # key with no `user_id_field` override needed.
    test "the foreign key follows `user_relationship_name` when `user_id_field` is left unset" do
      account_module_name =
        "AshAuthentication.WebAuthnCredential.VerifierTest.Account#{System.unique_integer([:positive])}"

      credential_module_name =
        "AshAuthentication.WebAuthnCredential.VerifierTest.Credential#{System.unique_integer([:positive])}"

      account_source = """
      defmodule #{account_module_name} do
        @moduledoc false
        use Ash.Resource,
          domain: AshAuthentication.Test.PermissiveDomain,
          data_layer: Ash.DataLayer.Ets

        ets do
          private?(true)
        end

        attributes do
          uuid_primary_key(:id)
        end
      end
      """

      credential_source = """
      defmodule #{credential_module_name} do
        @moduledoc false
        use Ash.Resource,
          domain: AshAuthentication.Test.PermissiveDomain,
          data_layer: Ash.DataLayer.Ets,
          extensions: [AshAuthentication.WebAuthnCredential]

        ets do
          private?(true)
        end

        webauthn_credential do
          user_resource(#{account_module_name})
          user_relationship_name(:account)
        end

        identities do
          identity :unique_credential_id, [:credential_id],
            pre_check_with: AshAuthentication.Test.PermissiveDomain
        end
      end
      """

      account_module = Module.concat([account_module_name])
      credential_module = Module.concat([credential_module_name])

      compiled = Code.compile_string(account_source <> "\n" <> credential_source)
      {^credential_module, _bytecode} = List.keyfind(compiled, credential_module, 0)

      relationship = ResourceInfo.relationship(credential_module, :account)

      assert relationship,
             "expected a `:account` relationship on #{inspect(credential_module)} (configured via " <>
               "`user_relationship_name(:account)`), but none was found — check " <>
               "ResourceInfo.relationships(#{inspect(credential_module)}) for what actually got built"

      assert %{
               type: :belongs_to,
               destination: ^account_module,
               source_attribute: :account_id,
               destination_attribute: :id
             } = relationship

      # The create action's `accept` list must use the *resolved* attribute
      # name (`:account_id`), not the pre-resolution `nil` — this is what
      # regresses if `user_id_field`'s value is read before the belongs_to
      # relationship (and its `<name>_id` default) has been built.
      assert :account_id in (credential_module
                             |> ResourceInfo.action(:create)
                             |> Map.fetch!(:accept))
    end
  end

  describe "attribute validation" do
    test "a pre-declared `label` attribute of the wrong type raises a friendly DslError" do
      error =
        assert_raise Spark.Error.DslError, fn ->
          compile_credential_with!(attributes: "attribute :label, :integer, public?: true")
        end

      assert error.message =~ "label"
      assert error.message =~ "Ash.Type.String"
    end

    test "a pre-declared `last_used_at` attribute of the wrong type raises a friendly DslError" do
      error =
        assert_raise Spark.Error.DslError, fn ->
          compile_credential_with!(attributes: "attribute :last_used_at, :string, public?: true")
        end

      assert error.message =~ "last_used_at"
      assert error.message =~ "Ash.Type.UtcDatetimeUsec"
    end
  end

  describe "unique_credential_id identity" do
    test "a `unique_credential_id` identity that omits the credential id field raises" do
      error =
        assert_raise Spark.Error.DslError, fn ->
          compile_credential_with!(
            identities:
              "identity :unique_credential_id, [:sign_count], " <>
                "pre_check_with: AshAuthentication.Test.PermissiveDomain"
          )
        end

      assert error.message =~ "unique_credential_id"
      assert error.message =~ "credential_id"
    end
  end

  # Like `compile_credential!/1`, but lets a test inject extra `attributes`
  # and/or `identities` DSL so it can exercise the credential resource's
  # attribute/identity validations.
  defp compile_credential_with!(opts) do
    module_name =
      "AshAuthentication.WebAuthnCredential.VerifierTest.Credential#{System.unique_integer([:positive])}"

    attributes = Keyword.get(opts, :attributes, "")
    identities = Keyword.get(opts, :identities, "")

    source = """
    defmodule #{module_name} do
      @moduledoc false
      use Ash.Resource,
        domain: AshAuthentication.Test.PermissiveDomain,
        data_layer: Ash.DataLayer.Ets,
        extensions: [AshAuthentication.WebAuthnCredential]

      ets do
        private?(true)
      end

      webauthn_credential do
        user_resource(Example.UserWithWebAuthn)
      end

      attributes do
        #{attributes}
      end

      identities do
        #{identities}
      end
    end
    """

    module = Module.concat([module_name])
    compiled = Code.compile_string(source)
    {^module, _bytecode} = List.keyfind(compiled, module, 0)
    module
  end

  # Compiles a fresh, throwaway WebAuthn credential resource from a string
  # source fixture, so each test can exercise
  # `AshAuthentication.WebAuthnCredential`'s transformer/verifier pipeline
  # end-to-end (this is inherently a cross-transformer-ordering concern, not
  # something a plain function call can exercise).
  defp compile_credential!(opts \\ []) do
    module_name =
      "AshAuthentication.WebAuthnCredential.VerifierTest.Credential#{System.unique_integer([:positive])}"

    relationships = Keyword.get(opts, :relationships, "")

    source =
      @credential_source
      |> String.replace("<%= module %>", module_name)
      |> String.replace("<%= relationships %>", relationships)

    module = Module.concat([module_name])
    compiled = Code.compile_string(source)
    {^module, _bytecode} = List.keyfind(compiled, module, 0)
    module
  end
end
