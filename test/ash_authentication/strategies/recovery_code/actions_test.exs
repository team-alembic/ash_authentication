# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

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

      refute MapSet.equal?(MapSet.new(first_codes), MapSet.new(second_codes))
      assert length(second_codes) == strategy.recovery_code_count

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

      assert {:ok, _user} = Actions.verify(strategy, %{user: user, code: code}, [])

      assert {:error, %AuthenticationFailed{}} =
               Actions.verify(strategy, %{user: user, code: code}, [])
    end

    test "using one code does not invalidate other codes" do
      user = build_user_with_recovery_codes()
      {:ok, strategy} = Info.strategy(Example.UserWithRecoveryCodes, :recovery_code)

      {_user, codes} = generate_codes(strategy, user)
      [first_code, second_code | _rest] = codes

      assert {:ok, _user} = Actions.verify(strategy, %{user: user, code: first_code}, [])
      assert {:ok, _user} = Actions.verify(strategy, %{user: user, code: second_code}, [])
    end
  end

  describe "hash provider context passing" do
    defmodule ContextTrackingProvider do
      @moduledoc false
      @behaviour AshAuthentication.HashProvider

      @impl true
      def hash(input), do: {:ok, "no_context:#{input}"}

      @impl true
      def hash(input, context) do
        marker = Map.get(context, :test_marker, "none")
        {:ok, "ctx_#{marker}:#{input}"}
      end

      @impl true
      def valid?(input, hash), do: hash == elem(hash(input), 1)
      @impl true
      def simulate, do: false
      @impl true
      def minimum_entropy, do: 0
      @impl true
      def deterministic?, do: true
    end

    test "call_hash/3 prefers hash/2 when implemented" do
      context = %{test_marker: "hello"}

      assert {:ok, "ctx_hello:test"} =
               AshAuthentication.HashProvider.call_hash(ContextTrackingProvider, "test", context)
    end

    test "call_hash/3 falls back to hash/1 for providers without hash/2" do
      assert {:ok, _} =
               AshAuthentication.HashProvider.call_hash(
                 AshAuthentication.SHA256Provider,
                 "test",
                 %{some: "context"}
               )
    end
  end

  describe "generate_code/2" do
    test "generates a code of the specified length" do
      code = Actions.generate_code(12, "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
      assert String.length(code) == 12
    end

    test "generates unique codes" do
      alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      codes = Enum.map(1..100, fn _ -> Actions.generate_code(12, alphabet) end)
      assert length(Enum.uniq(codes)) == 100
    end

    test "only uses characters from the provided alphabet" do
      alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
      allowed = String.graphemes(alphabet) |> MapSet.new()

      codes = Enum.map(1..100, fn _ -> Actions.generate_code(12, alphabet) end)

      for code <- codes, char <- String.graphemes(code) do
        assert char in allowed,
               "Code #{code} contains character not in alphabet: #{char}"
      end
    end
  end
end
