defmodule AshAuthentication.Strategy.RecoveryCode.VerifyAction do
  @moduledoc """
  Implementation of the recovery code verify action.

  This module is used as the `run` implementation for the verify action,
  which checks if a provided recovery code matches any of the user's
  stored hashed codes. On success, the matched code is deleted (single-use).
  """
  use Ash.Resource.Actions.Implementation
  require Ash.Query
  import Ash.Expr, only: [ref: 1]
  alias Ash.ActionInput
  alias AshAuthentication.Info

  require Logger

  @doc false
  @impl true
  def run(input, _opts, context) do
    user = ActionInput.get_argument(input, :user)
    code = ActionInput.get_argument(input, :code)

    opts =
      context
      |> Ash.Context.to_opts()

    load_opts = Keyword.merge(opts, lazy?: true, reuse_values?: true)

    {:ok, strategy} = Info.strategy_for_action(input.resource, input.action.name)

    if strategy.use_shared_salt? do
      verify_with_shared_salt(user, code, strategy, opts)
    else
      with {:ok, user_with_codes} <- load_recovery_codes(user, strategy, load_opts),
           {:ok, matched_code} <- find_matching_code(user_with_codes, code, strategy) do
        delete_recovery_code(matched_code, opts)
        {:ok, user}
      else
        {:error, :no_matching_code} ->
          {:ok, nil}

        {:error, error} ->
          {:error, error}
      end
    end
  end

  defp load_recovery_codes(user, strategy, load_opts) do
    Ash.load(user, [{strategy.recovery_codes_relationship_name, []}], load_opts)
  end

  defp find_matching_code(user, provided_code, strategy) do
    recovery_codes = Map.get(user, strategy.recovery_codes_relationship_name) || []

    matched =
      Enum.find(recovery_codes, fn code_record ->
        stored_hash = Map.get(code_record, strategy.code_field)
        strategy.hash_provider.valid?(provided_code, stored_hash)
      end)

    if matched do
      {:ok, matched}
    else
      # Simulate verification to prevent timing attacks
      strategy.hash_provider.simulate()
      {:error, :no_matching_code}
    end
  end

  # sobelow_skip ["DOS.BinToAtom"]
  defp verify_with_shared_salt(user, code, strategy, opts) do
    code_field = strategy.code_field
    user_id_field = :"#{strategy.user_relationship_name}_id"

    # Fetch one code to extract the shared salt
    first_record =
      strategy.recovery_code_resource
      |> Ash.Query.filter(^ref(user_id_field) == ^user.id)
      |> Ash.Query.limit(1)
      |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
      |> Ash.read_one!(opts)

    case first_record do
      nil ->
        # Simulate to prevent timing-based user enumeration
        strategy.hash_provider.simulate()
        {:ok, nil}

      record ->
        stored_hash = Map.get(record, code_field)
        salt = strategy.hash_provider.extract_salt(stored_hash)
        iterations = strategy.hash_provider.extract_iterations(stored_hash)
        {:ok, hashed_input} = strategy.hash_provider.hash(code, salt, iterations: iterations)

        # Direct DB lookup by hashed value
        matched =
          strategy.recovery_code_resource
          |> Ash.Query.filter(
            ^ref(user_id_field) == ^user.id and ^ref(code_field) == ^hashed_input
          )
          |> Ash.Query.set_context(%{private: %{ash_authentication?: true}})
          |> Ash.read_one!(opts)

        if matched do
          delete_recovery_code(matched, opts)
          {:ok, user}
        else
          strategy.hash_provider.simulate()
          {:ok, nil}
        end
    end
  end

  defp delete_recovery_code(recovery_code, opts) do
    recovery_code
    |> Ash.Changeset.new()
    |> Ash.Changeset.set_context(%{private: %{ash_authentication?: true}})
    |> Ash.Changeset.for_destroy(:destroy, %{}, opts)
    |> Ash.destroy!()
  end
end
