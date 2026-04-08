defmodule AshAuthentication.Strategy.RecoveryCode.Actions do
  @moduledoc """
  Actions for the recovery code strategy.

  Provides the code interface for recovery code verification and generation.
  """

  alias Ash.{ActionInput, Changeset}
  alias AshAuthentication.{Errors, Info, Strategy.RecoveryCode}

  @doc """
  Verify a recovery code for a user.

  Takes a user and a recovery code, verifies against stored hashed codes,
  deletes the code on success, and returns the authenticated user.
  """
  @spec verify(RecoveryCode.t(), map, keyword) ::
          {:ok, Ash.Resource.record()} | {:error, any}
  def verify(strategy, params, options) do
    options =
      options
      |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

    strategy.resource
    |> ActionInput.new()
    |> ActionInput.set_context(%{private: %{ash_authentication?: true}})
    |> ActionInput.for_action(strategy.verify_action_name, params, options)
    |> Ash.run_action()
    |> case do
      {:ok, user} when not is_nil(user) ->
        {:ok, user}

      {:ok, nil} ->
        {:error,
         Errors.AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: %{
             module: __MODULE__,
             strategy: strategy,
             action: :verify,
             message: "Invalid recovery code"
           }
         )}

      {:error, error} ->
        {:error,
         Errors.AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: error
         )}
    end
  end

  @doc """
  Generate new recovery codes for a user.

  Deletes any existing recovery codes and generates new ones.
  Returns the user with plaintext codes in `__metadata__.recovery_codes`.
  """
  @spec generate(RecoveryCode.t(), map, keyword) ::
          {:ok, Ash.Resource.record()} | {:error, any}
  def generate(strategy, params, options) do
    user = Map.get(params, :user) || Map.get(params, "user")

    options =
      options
      |> Keyword.put_new_lazy(:domain, fn -> Info.domain!(strategy.resource) end)

    user
    |> Changeset.new()
    |> Changeset.set_context(%{private: %{ash_authentication?: true}})
    |> Changeset.for_update(strategy.generate_action_name, %{}, options)
    |> Ash.update()
    |> case do
      {:ok, user} ->
        {:ok, user}

      {:error, error} ->
        {:error,
         Errors.AuthenticationFailed.exception(
           strategy: strategy,
           caused_by: error
         )}
    end
  end

  @doc """
  Generate a list of random recovery codes using a CSPRNG.
  """
  @spec generate_codes_list(pos_integer, pos_integer, String.t()) :: [String.t()]
  def generate_codes_list(length, count, alphabet) do
    Enum.map(1..count, fn _ -> generate_code(length, alphabet) end)
  end

  @doc """
  Generate a single random recovery code using `:crypto.strong_rand_bytes/1`.
  """
  @spec generate_code(pos_integer, String.t()) :: String.t()
  def generate_code(length, alphabet) do
    alphabet_list = String.graphemes(alphabet)
    alphabet_size = length(alphabet_list)

    length
    |> :crypto.strong_rand_bytes()
    |> :binary.bin_to_list()
    |> Enum.map(fn byte -> Enum.at(alphabet_list, rem(byte, alphabet_size)) end)
    |> Enum.join()
  end
end
