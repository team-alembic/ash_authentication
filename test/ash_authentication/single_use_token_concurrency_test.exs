# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.SingleUseTokenConcurrencyTest do
  @moduledoc """
  Asserts that a single-use token is redeemable exactly once when the
  redemptions arrive concurrently.

  Three read actions share the shape this covers: the token is verified, the
  record is resolved, and only then is the token revoked in a
  `Query.after_action/2` hook. Read actions are not transactional, so the
  revocation itself has to be the serialisation point.

  Sequential reuse is rejected even when the revocation is not serialised, so
  only a concurrent test can hold this property.

  Every process here runs `Sandbox.unboxed_run/2`, which gives it its own real
  connection that commits. A sandboxed test cannot show anything about this
  race: it would share one connection inside one transaction, which has neither
  the row locks nor the commit boundaries that decide the outcome. Because the
  writes are real, each test removes its own rows afterwards.
  """

  use ExUnit.Case, async: false

  alias AshAuthentication.Errors.InvalidToken
  alias AshAuthentication.{Info, Jwt, Strategy, Strategy.MagicLink}
  alias Ecto.Adapters.SQL.Sandbox

  @concurrent_redemptions 24

  describe "magic link sign_in_with_magic_link" do
    test "with `store_all_tokens?` enabled, exactly one concurrent redemption succeeds" do
      unboxed(fn -> assert_redeemable_once(Example.User, :magic_link) end)
    end

    test "with `store_all_tokens?` disabled, exactly one concurrent redemption succeeds" do
      unboxed(fn ->
        assert_redeemable_once(Example.UserWithSelectiveStrategyIncludes, :magic_link)
      end)
    end
  end

  describe "password sign_in_with_token" do
    test "with `store_all_tokens?` enabled, exactly one concurrent redemption succeeds" do
      unboxed(fn -> assert_redeemable_once(Example.User, :password) end)
    end

    test "with `store_all_tokens?` disabled, exactly one concurrent redemption succeeds" do
      unboxed(fn -> assert_redeemable_once(Example.UserWithUnstoredSignInTokens, :password) end)
    end
  end

  describe "webauthn sign_in_with_token" do
    test "with `store_all_tokens?` enabled, exactly one concurrent redemption succeeds" do
      unboxed(fn -> assert_redeemable_once(Example.UserWithWebAuthn, :webauthn) end)
    end

    test "with `store_all_tokens?` disabled, exactly one concurrent redemption succeeds" do
      unboxed(fn -> assert_redeemable_once(Example.UserWithUnstoredWebAuthn, :webauthn) end)
    end
  end

  defp assert_redeemable_once(resource, strategy_name) do
    strategy = Info.strategy!(resource, strategy_name)
    {subject, token} = mint_single_use_token(resource, strategy)
    on_exit(fn -> unboxed(fn -> purge(resource, subject) end) end)

    results =
      fire_together(@concurrent_redemptions, fn -> redeem(resource, strategy, token) end)

    successes = Enum.count(results, &match?({:ok, _}, &1))
    errors = for {:error, error} <- results, do: error

    assert successes == 1
    assert length(errors) == @concurrent_redemptions - 1

    # A loser that reached the revocation reports the conflict. A loser whose
    # verification happened to run after the winner committed is rejected
    # earlier instead, which is also an observable failure but says nothing
    # about serialisation — so require that at least one lost at the revocation.
    assert Enum.any?(errors, &revocation_conflict?/1)
  end

  defp revocation_conflict?(%InvalidToken{type: :revocation}), do: true

  defp revocation_conflict?(error) when is_map(error) do
    error
    |> Map.get(:errors)
    |> List.wrap()
    |> Enum.concat(List.wrap(Map.get(error, :caused_by)))
    |> Enum.any?(&revocation_conflict?/1)
  end

  defp revocation_conflict?(_), do: false

  defp redeem(_resource, %MagicLink{} = strategy, token),
    do: MagicLink.Actions.sign_in(strategy, %{"token" => token}, [])

  defp redeem(resource, strategy, token) do
    resource
    |> Ash.Query.new()
    |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
    |> Ash.Query.for_read(strategy.sign_in_with_token_action_name, %{token: token})
    |> Ash.read()
    |> case do
      {:ok, [user]} -> {:ok, user}
      {:ok, other} -> {:error, "expected one user, got #{length(other)}"}
      {:error, error} -> {:error, error}
    end
  end

  defp mint_single_use_token(resource, %MagicLink{} = strategy) do
    user = build_subject(resource, strategy)
    {:ok, token} = MagicLink.request_token_for(strategy, user)
    {user.id, token}
  end

  defp mint_single_use_token(resource, %Strategy.Password{} = strategy) do
    user = build_subject(resource, strategy)
    field = strategy.identity_field
    password = password()

    {:ok, signed_in} =
      Strategy.action(
        strategy,
        :sign_in,
        %{field => to_string(Map.fetch!(user, field)), :password => password},
        context: [token_type: :sign_in]
      )

    {user.id, signed_in.__metadata__.token}
  end

  defp mint_single_use_token(resource, strategy) do
    user = build_subject(resource, strategy)

    # Mint the way the ceremony does, so the test covers redemption rather than
    # re-running a WebAuthn assertion.
    {:ok, token, _claims} = Jwt.token_for_user(user, %{"purpose" => "sign_in"}, [])

    {user.id, token}
  end

  defp build_subject(resource, %Strategy.WebAuthn{}) do
    resource
    |> Ash.Changeset.for_create(:create, %{email: email()})
    |> Ash.create!()
  end

  defp build_subject(resource, strategy) do
    password = password()

    resource
    |> Ash.Changeset.for_create(:register_with_password, %{
      strategy.identity_field => email(),
      :password => password,
      :password_confirmation => password
    })
    |> Ash.create!()
  end

  # Every task takes its connection and then blocks, so neither the checkout nor
  # the process spawn falls inside the window under test. Releasing them all
  # from one message overlaps the redemptions tightly enough that unserialised
  # revocation reliably lets several through.
  defp fire_together(count, fun) do
    parent = self()
    tasks = for _ <- 1..count, do: Task.async(fn -> run_on_signal(parent, fun) end)

    for _ <- 1..count, do: assert_receive({:ready, _}, 30_000)
    for task <- tasks, do: send(task.pid, :go)

    Task.await_many(tasks, 60_000)
  end

  defp run_on_signal(parent, fun) do
    unboxed(fn ->
      Example.Repo.query!("SELECT 1")
      send(parent, {:ready, self()})

      receive do
        :go -> fun.()
      end
    end)
  end

  # The writes are real, so anything they left has to go before the next test
  # observes the shared tables.
  defp purge(resource, user_id) do
    table = AshPostgres.DataLayer.Info.table(resource)
    id = to_string(user_id)

    Example.Repo.query!("DELETE FROM tokens WHERE subject LIKE $1", ["%#{id}%"])
    Example.Repo.query!("DELETE FROM audit_logs WHERE subject LIKE $1", ["%#{id}%"])
    Example.Repo.query!("DELETE FROM \"#{table}\" WHERE id::text = $1", [id])
  end

  defp email, do: "concurrent_#{System.unique_integer([:positive])}@example.com"
  defp password, do: "correct horse battery staple"
  defp unboxed(fun), do: Sandbox.unboxed_run(Example.Repo, fun)
end
