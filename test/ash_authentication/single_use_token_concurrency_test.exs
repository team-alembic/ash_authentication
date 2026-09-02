# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.SingleUseTokenConcurrencyTest do
  @moduledoc """
  Asserts that a single-use token is redeemable exactly once when the
  redemptions arrive concurrently.

  Two read actions share the shape this covers: the token is verified, the
  record is resolved, and only then is the token revoked in a
  `Query.after_action/2` hook. Read actions are not transactional, so the
  revocation itself has to be the serialisation point. The registration-enabled
  magic link create action is covered too, since its revoke runs in a hook of
  the enclosing transaction rather than spanning the check.

  Sequential reuse is rejected even when the revocation is not serialised, so
  only a concurrent test can hold this property.

  Every process here runs `Sandbox.unboxed_run/2`, which gives it its own real
  connection that commits. A sandboxed test cannot show anything about this
  race: it would share one connection inside one transaction, which has neither
  the row locks nor the commit boundaries that decide the outcome. Because the
  writes are real, each test removes its own rows afterwards.
  """

  use ExUnit.Case, async: false

  import ExUnit.CaptureLog

  alias AshAuthentication.Errors.InvalidToken
  alias AshAuthentication.{Info, Jwt, Strategy, Strategy.MagicLink}
  alias Ecto.Adapters.SQL.Sandbox

  @concurrent_redemptions 24

  describe "magic link sign_in_with_magic_link (read action)" do
    test "with `store_all_tokens?` enabled, exactly one concurrent redemption succeeds" do
      unboxed(fn -> assert_redeemable_once(Example.User, :magic_link) end)
    end

    test "with `store_all_tokens?` disabled, exactly one concurrent redemption succeeds" do
      unboxed(fn ->
        assert_redeemable_once(Example.UserWithSelectiveStrategyIncludes, :magic_link)
      end)
    end
  end

  describe "magic link sign_in_with_magic_link (registration-enabled create action)" do
    test "exactly one concurrent redemption succeeds" do
      unboxed(fn -> assert_registration_redeemable_once() end)
    end
  end

  describe "password sign_in_with_token (read action)" do
    test "with `store_all_tokens?` enabled, exactly one concurrent redemption succeeds" do
      unboxed(fn -> assert_redeemable_once(Example.User, :password) end)
    end

    test "with `store_all_tokens?` disabled, exactly one concurrent redemption succeeds" do
      unboxed(fn -> assert_redeemable_once(Example.UserWithUnstoredSignInTokens, :password) end)
    end
  end

  defp assert_redeemable_once(resource, strategy_name) do
    strategy = Info.strategy!(resource, strategy_name)
    user = build_subject(resource, strategy)
    token = mint_single_use_token(user, strategy)
    on_exit(fn -> unboxed(fn -> purge(resource, user.id) end) end)

    assert_exactly_one_wins(fn -> redeem(resource, strategy, token) end)
  end

  defp assert_registration_redeemable_once do
    resource = Example.UserWithRegisterMagicLink
    strategy = Info.strategy!(resource, :magic_link)
    email = email()
    token = request_registration_token(strategy, email)

    # The requested token's subject carries no id, because the user does not
    # exist yet, so it is not reachable by the per-user purge.
    {:ok, %{"jti" => jti}} = Jwt.peek(token)

    on_exit(fn ->
      unboxed(fn ->
        purge_by_email(resource, email)
        Example.Repo.query!("DELETE FROM tokens WHERE jti = $1", [jti])
      end)
    end)

    assert_exactly_one_wins(fn ->
      MagicLink.Actions.sign_in(strategy, %{"token" => token}, [])
    end)
  end

  defp assert_exactly_one_wins(redeem) do
    results = fire_together(@concurrent_redemptions, redeem)

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

  defp mint_single_use_token(user, %MagicLink{} = strategy) do
    {:ok, token} = MagicLink.request_token_for(strategy, user)
    token
  end

  defp mint_single_use_token(user, strategy) do
    field = strategy.identity_field

    {:ok, signed_in} =
      Strategy.action(
        strategy,
        :sign_in,
        %{field => to_string(Map.fetch!(user, field)), :password => password()},
        context: [token_type: :sign_in]
      )

    signed_in.__metadata__.token
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

  defp request_registration_token(strategy, email) do
    log = capture_log(fn -> MagicLink.Actions.request(strategy, %{"email" => email}, []) end)

    log
    |> String.split("Magic link request for #{email}, token \"", parts: 2)
    |> Enum.at(1)
    |> String.split("\"", parts: 2)
    |> Enum.at(0)
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

  defp purge_by_email(resource, email) do
    table = AshPostgres.DataLayer.Info.table(resource)

    %{rows: rows} =
      Example.Repo.query!("SELECT id::text FROM \"#{table}\" WHERE email = $1", [email])

    for [id] <- rows, do: purge(resource, id)
  end

  defp email, do: "concurrent_#{System.unique_integer([:positive])}@example.com"
  defp password, do: "correct horse battery staple"
  defp unboxed(fun), do: Sandbox.unboxed_run(Example.Repo, fun)
end
