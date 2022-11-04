defmodule AshAuthentication.Confirmation.ConfirmChange do
  @moduledoc """
  Performs a change based on the contents of a confirmation token.
  """

  use Ash.Resource.Change
  alias AshAuthentication.{Confirmation.Info, Jwt}
  alias Ash.{Changeset, Error.Changes.InvalidArgument, Resource.Change}

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, _) do
    changeset
    |> Changeset.before_action(fn changeset ->
      with token when is_binary(token) <- Changeset.get_argument(changeset, :confirm),
           {:ok, %{"act" => token_action, "chg" => changes}, _} <-
             Jwt.verify(token, changeset.resource),
           {:ok, resource_action} <- Info.confirm_action_name(changeset.resource),
           true <- to_string(resource_action) == token_action,
           {:ok, allowed_fields} <- Info.monitor_fields(changeset.resource),
           {:ok, confirmed_at} <- Info.confirmed_at_field(changeset.resource) do
        allowed_changes =
          changes
          |> Map.take(Enum.map(allowed_fields, &to_string/1))

        changeset
        |> Changeset.change_attributes(allowed_changes)
        |> Changeset.change_attribute(confirmed_at, DateTime.utc_now())
      else
        _ -> {:error, InvalidArgument.exception(field: :confirm, message: "is not valid")}
      end
    end)
  end
end
