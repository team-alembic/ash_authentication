defmodule AshAuthentication.Strategy.RecoveryCode.Actions do
  @moduledoc """
  Actions for the recovery code strategy.

  Provides the code interface for recovery code verification and generation.
  """

  alias Ash.{ActionInput, Changeset}
  alias AshAuthentication.{Errors, Info, Strategy.RecoveryCode}

  # Character set excluding ambiguous characters (1, I, O, o, 0)
  @allowed_chars ~c"abcdefghjkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789"

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
  Generate a list of random recovery codes.
  """
  @spec generate_codes_list(pos_integer, pos_integer) :: [String.t()]
  def generate_codes_list(length, count) do
    Enum.map(1..count, fn _ -> generate_code(length) end)
  end

  @doc """
  Generate a single random recovery code.

  Returns a random string of the configured length using an unambiguous
  character set (excluding 1, I, O, o, 0).
  """
  @spec generate_code(pos_integer) :: String.t()
  def generate_code(length) do
    Enum.map_join(1..length, fn _ ->
      <<Enum.random(@allowed_chars)::utf8>>
    end)
  end
end
