defmodule AshAuthentication.PasswordAuthentication.HashPasswordChange do
  @moduledoc """
  Set the hash based on the password input.

  Uses the configured `AshAuthentication.HashProvider` to generate a hash of the
  user's password input and store it in the changeset.
  """

  use Ash.Resource.Change
  alias AshAuthentication.PasswordAuthentication.Info
  alias Ash.{Changeset, Resource.Change}

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, _) do
    changeset
    |> Changeset.before_action(fn changeset ->
      {:ok, password_field} = Info.password_field(changeset.resource)
      {:ok, hash_field} = Info.hashed_password_field(changeset.resource)
      {:ok, hasher} = Info.hash_provider(changeset.resource)

      with value when is_binary(value) <- Changeset.get_argument(changeset, password_field),
           {:ok, hash} <- hasher.hash(value) do
        Changeset.change_attribute(changeset, hash_field, hash)
      else
        nil -> changeset
        :error -> {:error, "Error hashing password"}
      end
    end)
  end
end
