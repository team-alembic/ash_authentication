defmodule AshAuthentication.PasswordReset.RequestPasswordResetAction do
  @moduledoc """
  A manually implemented action which generates a reset token for a user.
  """
  use Ash.Resource.ManualUpdate
  alias Ash.{Changeset, Resource, Resource.ManualUpdate}
  alias AshAuthentication.{Jwt, PasswordReset.Info}

  @doc false
  @impl true
  @spec update(Changeset.t(), keyword, ManualUpdate.context()) ::
          {:ok, Resource.record()} | {:error, any}
  def update(changeset, _opts, _context) do
    lifetime = Info.token_lifetime!(changeset.resource)

    action =
      changeset.action
      |> Map.fetch!(:name)
      |> to_string()

    {:ok, token, _claims} =
      changeset.data
      |> Jwt.token_for_record(%{"act" => action}, token_lifetime: lifetime)

    metadata =
      changeset.data.__metadata__
      |> Map.put(:reset_token, token)

    data =
      changeset.data
      |> Map.put(:__metadata__, metadata)

    {:ok, data}
  end
end
