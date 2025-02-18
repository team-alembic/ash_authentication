defmodule ExampleMultiTenant.GenericOAuth2Change do
  @moduledoc false
  use Ash.Resource.Change
  alias Ash.{Changeset, Resource.Change}

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, _context) do
    user_info = Changeset.get_argument(changeset, :user_info)

    username =
      user_info["nickname"] || user_info["login"] || user_info["preferred_username"] ||
        user_info["email"]

    changeset
    |> Changeset.change_attribute(:username, username)
  end
end
