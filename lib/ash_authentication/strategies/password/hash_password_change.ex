defmodule AshAuthentication.Strategy.Password.HashPasswordChange do
  @moduledoc """
  Set the hash based on the password input.

  Uses the configured `AshAuthentication.HashProvider` to generate a hash of the
  user's password input and store it in the changeset.
  """

  use Ash.Resource.Change
  alias Ash.{Changeset, Error.Framework.AssumptionFailed, Resource.Change}

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, _) do
    changeset
    |> Changeset.before_action(fn changeset ->
      with {:ok, strategy} <- Map.fetch(changeset.context, :strategy),
           value when is_binary(value) <-
             Changeset.get_argument(changeset, strategy.password_field),
           {:ok, hash} <- strategy.hash_provider.hash(value) do
        Changeset.change_attribute(changeset, strategy.hashed_password_field, hash)
      else
        :error ->
          raise AssumptionFailed, message: "Error hashing password."

        _ ->
          changeset
      end
    end)
  end
end
