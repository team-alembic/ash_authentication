defmodule AshAuthentication.Strategy.RecoveryCode.PlugTest do
  @moduledoc false
  use DataCase
  import Plug.Test

  alias AshAuthentication.{
    Errors.AuthenticationFailed,
    Info,
    Plug.Helpers,
    Strategy,
    Strategy.RecoveryCode.Plug
  }

  describe "verify/2" do
    test "it verifies a valid recovery code" do
      {:ok, strategy} = Info.strategy(Example.UserWithRecoveryCodes, :recovery_code)
      user = build_user_with_recovery_codes()

      {:ok, user} = Strategy.action(strategy, :generate, %{user: user}, [])
      code = List.first(user.__metadata__.recovery_codes)

      params = %{
        "user_with_recovery_codes" => %{
          "code" => code
        }
      }

      assert {_conn, {:ok, verified_user}} =
               :post
               |> conn("/", params)
               |> Ash.PlugHelpers.set_actor(user)
               |> Plug.verify(strategy)
               |> Helpers.get_authentication_result()

      assert verified_user.id == user.id
      assert verified_user.__metadata__.recovery_code_used_at
    end

    test "it returns an error for an invalid code" do
      {:ok, strategy} = Info.strategy(Example.UserWithRecoveryCodes, :recovery_code)
      user = build_user_with_recovery_codes()

      {:ok, user} = Strategy.action(strategy, :generate, %{user: user}, [])

      params = %{
        "user_with_recovery_codes" => %{
          "code" => "invalidcode"
        }
      }

      assert {_conn, {:error, %AuthenticationFailed{}}} =
               :post
               |> conn("/", params)
               |> Ash.PlugHelpers.set_actor(user)
               |> Plug.verify(strategy)
               |> Helpers.get_authentication_result()
    end
  end

  describe "generate/2" do
    test "it generates recovery codes for the user" do
      {:ok, strategy} = Info.strategy(Example.UserWithRecoveryCodes, :recovery_code)
      user = build_user_with_recovery_codes()

      assert {_conn, {:ok, updated_user}} =
               :post
               |> conn("/")
               |> Ash.PlugHelpers.set_actor(user)
               |> Plug.generate(strategy)
               |> Helpers.get_authentication_result()

      codes = updated_user.__metadata__.recovery_codes
      assert length(codes) == strategy.recovery_code_count
      assert Enum.all?(codes, &is_binary/1)
    end
  end
end
