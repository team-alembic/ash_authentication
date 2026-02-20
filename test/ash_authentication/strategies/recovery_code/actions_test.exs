defmodule AshAuthentication.Strategy.RecoveryCode.ActionsTest do
  @moduledoc false
  use DataCase

  alias AshAuthentication.{
    Errors.AuthenticationFailed,
    Info,
    Strategy,
    Strategy.RecoveryCode.Actions
  }

  defp generate_codes(strategy, user) do
    {:ok, user} = Strategy.action(strategy, :generate, %{user: user}, [])
    {user, user.__metadata__.recovery_codes}
  end

  describe "generate/3" do
    test "it generates the configured number of recovery codes" do
      user = build_user_with_recovery_codes()
      {:ok, strategy} = Info.strategy(Example.UserWithRecoveryCodes, :recovery_code)

      {_user, codes} = generate_codes(strategy, user)

      assert length(codes) == strategy.recovery_code_count
      assert Enum.all?(codes, &is_binary/1)
      assert Enum.all?(codes, &(String.length(&1) == strategy.code_length))
    end

    test "regenerating codes deletes old ones" do
      user = build_user_with_recovery_codes()
      {:ok, strategy} = Info.strategy(Example.UserWithRecoveryCodes, :recovery_code)

      {user, first_codes} = generate_codes(strategy, user)
      {_user, second_codes} = generate_codes(strategy, user)

      # New codes should be different from old ones
      refute MapSet.equal?(MapSet.new(first_codes), MapSet.new(second_codes))

      # Should still have the same count
      assert length(second_codes) == strategy.recovery_code_count

      # Verify that old codes no longer work
      first_code = List.first(first_codes)

      assert {:error, %AuthenticationFailed{}} =
               Actions.verify(strategy, %{user: user, code: first_code}, [])
    end
  end

  describe "verify/3" do
    test "it returns the user for a valid recovery code" do
      user = build_user_with_recovery_codes()
      {:ok, strategy} = Info.strategy(Example.UserWithRecoveryCodes, :recovery_code)

      {_user, codes} = generate_codes(strategy, user)
      code = List.first(codes)

      assert {:ok, verified_user} = Actions.verify(strategy, %{user: user, code: code}, [])
      assert verified_user.id == user.id
    end

    test "it returns an error for an invalid code" do
      user = build_user_with_recovery_codes()
      {:ok, strategy} = Info.strategy(Example.UserWithRecoveryCodes, :recovery_code)

      {_user, _codes} = generate_codes(strategy, user)

      assert {:error, %AuthenticationFailed{}} =
               Actions.verify(strategy, %{user: user, code: "invalidcode"}, [])
    end

    test "recovery codes are single-use (deleted after verification)" do
      user = build_user_with_recovery_codes()
      {:ok, strategy} = Info.strategy(Example.UserWithRecoveryCodes, :recovery_code)

      {_user, codes} = generate_codes(strategy, user)
      code = List.first(codes)

      # First use should succeed
      assert {:ok, _user} = Actions.verify(strategy, %{user: user, code: code}, [])

      # Second use of same code should fail
      assert {:error, %AuthenticationFailed{}} =
               Actions.verify(strategy, %{user: user, code: code}, [])
    end

    test "using one code does not invalidate other codes" do
      user = build_user_with_recovery_codes()
      {:ok, strategy} = Info.strategy(Example.UserWithRecoveryCodes, :recovery_code)

      {_user, codes} = generate_codes(strategy, user)
      [first_code, second_code | _rest] = codes

      # Use first code
      assert {:ok, _user} = Actions.verify(strategy, %{user: user, code: first_code}, [])

      # Second code should still work
      assert {:ok, _user} = Actions.verify(strategy, %{user: user, code: second_code}, [])
    end
  end

  describe "generate_code/1" do
    test "generates a code of the specified length" do
      code = Actions.generate_code(8)
      assert String.length(code) == 8
    end

    test "generates unique codes" do
      codes = Enum.map(1..100, fn _ -> Actions.generate_code(8) end)
      # All should be unique (statistically extremely unlikely to have duplicates)
      assert length(Enum.uniq(codes)) == 100
    end

    test "only uses unambiguous characters" do
      ambiguous = ~c"1IOo0l"

      codes = Enum.map(1..100, fn _ -> Actions.generate_code(8) end)

      for code <- codes, char <- String.to_charlist(code) do
        refute char in ambiguous,
               "Code #{code} contains ambiguous character: #{<<char::utf8>>}"
      end
    end
  end
end
