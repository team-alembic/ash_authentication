# SPDX-FileCopyrightText: 2022 Alembic Pty Ltd
#
# SPDX-License-Identifier: MIT

defmodule AshAuthentication.Strategy.RecoveryCode.VerifyAction do
  @moduledoc """
  Implementation of the recovery code verify action.

  Checks if a provided recovery code matches any of the user's stored hashed
  codes. On success, the matched code is deleted (single-use).

  Uses two verification strategies depending on the hash provider:

  - **Deterministic** (e.g. SHA-256): hashes the input once and performs an
    atomic database filter+delete via `Ash.bulk_destroy`. Inherently race-safe.
  - **Non-deterministic** (e.g. bcrypt): loads codes with `FOR UPDATE` locking,
    iterates with constant-time padding, then deletes by ID.
  """
  use Ash.Resource.Actions.Implementation
  require Ash.Query
  import Ash.Expr, only: [ref: 1]
  alias Ash.ActionInput
  alias AshAuthentication.Info

  @doc false
  @impl true
  def run(input, _opts, context) do
    user = ActionInput.get_argument(input, :user)
    code = ActionInput.get_argument(input, :code)

    opts = context |> Ash.Context.to_opts()

    {:ok, strategy} = Info.strategy_for_action(input.resource, input.action.name)

    if strategy.hash_provider.deterministic?() do
      verify_deterministic(user, code, strategy, opts)
    else
      verify_non_deterministic(user, code, strategy, opts)
    end
  end

  # sobelow_skip ["DOS.BinToAtom"]
  defp verify_deterministic(user, code, strategy, opts) do
    code_field = strategy.code_field
    user_id_field = :"#{strategy.user_relationship_name}_id"

    case strategy.hash_provider.hash(code) do
      {:ok, hashed_input} ->
        domain = Keyword.get_lazy(opts, :domain, fn -> Info.domain!(strategy.resource) end)

        result =
          strategy.recovery_code_resource
          |> Ash.Query.filter(
            ^ref(user_id_field) == ^user.id and ^ref(code_field) == ^hashed_input
          )
          |> Ash.Query.limit(1)
          |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
          |> Ash.bulk_destroy(:destroy, %{},
            strategy: [:atomic, :atomic_batches, :stream],
            return_records?: true,
            context: %{private: %{ash_authentication?: true}},
            domain: domain
          )

        case result do
          %{records: [_ | _]} -> {:ok, user}
          _ -> {:ok, nil}
        end

      :error ->
        strategy.hash_provider.simulate()
        {:ok, nil}
    end
  end

  # sobelow_skip ["DOS.BinToAtom"]
  defp verify_non_deterministic(user, code, strategy, opts) do
    code_field = strategy.code_field
    user_id_field = :"#{strategy.user_relationship_name}_id"
    domain = Keyword.get_lazy(opts, :domain, fn -> Info.domain!(strategy.resource) end)

    codes =
      strategy.recovery_code_resource
      |> Ash.Query.filter(^ref(user_id_field) == ^user.id)
      |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
      |> Ash.Query.lock(:for_update)
      |> Ash.read!(Keyword.merge(opts, domain: domain))

    matched = find_matching_code(codes, code, code_field, strategy)

    pad_count = max(0, strategy.recovery_code_count - length(codes))
    Enum.each(1..max(pad_count, 1)//1, fn _ -> strategy.hash_provider.simulate() end)

    case matched do
      nil ->
        {:ok, nil}

      matched_code ->
        strategy.recovery_code_resource
        |> Ash.Query.filter(id == ^matched_code.id)
        |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
        |> Ash.bulk_destroy(:destroy, %{},
          strategy: [:atomic, :atomic_batches, :stream],
          context: %{private: %{ash_authentication?: true}},
          domain: domain
        )

        {:ok, user}
    end
  end

  defp find_matching_code(codes, provided_code, code_field, strategy) do
    Enum.find(codes, fn code_record ->
      stored_hash = Map.get(code_record, code_field)
      strategy.hash_provider.valid?(provided_code, stored_hash)
    end)
  end
end
