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

      assert %{type: :belongs_to, destination: Example.UserWithWebAuthn, allow_nil?: false} =
               ResourceInfo.relationship(module, :user)
    end

    test "a manually-declared belongs_to pointing at the wrong resource still raises a friendly DslError" do
      error =
        assert_raise Spark.Error.DslError, fn ->
          compile_credential!(relationships: "belongs_to :user, Example.Token")
        end

      assert error.message =~ "user"
      assert error.message =~ "#{inspect(Example.UserWithWebAuthn)}"
    end
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
