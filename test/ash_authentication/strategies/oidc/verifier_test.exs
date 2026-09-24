# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.Oidc.VerifierTest do
  @moduledoc false
  use DataCase, async: true

  alias AshAuthentication.{Info, Strategy.Oidc.Verifier}
  alias Spark.Error.DslError

  use Mimic

  setup do
    {:ok, strategy} = Info.strategy(Example.User, :oidc)
    {:ok, strategy: strategy, dsl_state: Example.User.spark_dsl_config()}
  end

  describe "verify/2 private key validation" do
    test "a `private_key_jwt` client authentication method requires a private key", %{
      strategy: strategy,
      dsl_state: dsl_state
    } do
      strategy = %{
        strategy
        | client_authentication_method: "private_key_jwt",
          private_key: nil,
          private_key_path: nil
      }

      assert {:error, %DslError{} = error} = Verifier.verify(strategy, dsl_state)
      assert Exception.message(error) =~ "private_key"
    end

    test "`auth_method` no longer decides it, because Assent overwrites that field", %{
      strategy: strategy,
      dsl_state: dsl_state
    } do
      strategy = %{
        strategy
        | auth_method: :private_key_jwt,
          client_authentication_method: "client_secret_basic",
          private_key: nil,
          private_key_path: nil
      }

      refute match?({:error, _}, Verifier.verify(strategy, dsl_state))
    end
  end

  describe "verify/2 untrusted email match" do
    test "`on_untrusted_email_match :confirm` requires a confirmation add-on", %{
      strategy: strategy,
      dsl_state: dsl_state
    } do
      strategy = %{strategy | on_untrusted_email_match: :confirm}

      AshAuthentication.Info
      |> stub(:authentication_add_ons, fn _ -> [] end)

      assert {:error, %DslError{} = error} = Verifier.verify(strategy, dsl_state)
      assert Exception.message(error) =~ "no `confirmation` add-on is configured"
    end
  end
end
