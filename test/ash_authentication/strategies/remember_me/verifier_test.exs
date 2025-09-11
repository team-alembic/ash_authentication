defmodule AshAuthentication.Strategy.RememberMe.VerifierTest do
  @moduledoc false
  use ExUnit.Case, async: true

  alias AshAuthentication.Strategy.RememberMe
  alias AshAuthentication.Strategy.RememberMe.Verifier
  alias Spark.Error.DslError

  use Mimic

  describe "verify/2" do
    test "returns :ok when tokens are enabled" do
      strategy = %RememberMe{name: :remember_me}

      dsl_state = %{
        authentication: %{
          tokens: %{enabled?: true}
        }
      }

      AshAuthentication.Info
      |> expect(:authentication_tokens_enabled?, fn ^dsl_state -> true end)

      assert Verifier.verify(strategy, dsl_state) == :ok
    end

    test "returns error when tokens are disabled" do
      strategy = %RememberMe{name: :remember_me}

      dsl_state = %{
        authentication: %{
          tokens: %{enabled?: false}
        }
      }

      AshAuthentication.Info
      |> expect(:authentication_tokens_enabled?, fn ^dsl_state -> false end)

      result = Verifier.verify(strategy, dsl_state)

      assert {:error, %DslError{}} = result

      assert result |> elem(1) |> Map.get(:message) =~
               "The remmber me strategy requires that tokens are enabled"
    end
  end
end
