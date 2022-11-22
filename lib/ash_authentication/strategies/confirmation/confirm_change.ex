defmodule AshAuthentication.Strategy.Confirmation.ConfirmChange do
  @moduledoc """
  Performs a change based on the contents of a confirmation token.
  """

  use Ash.Resource.Change
  alias AshAuthentication.Jwt

  alias Ash.{
    Changeset,
    Error.Changes.InvalidArgument,
    Error.Framework.AssumptionFailed,
    Resource.Change
  }

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, _context) do
    case Map.fetch(changeset.context, :strategy) do
      {:ok, strategy} ->
        do_change(changeset, strategy)

      :error ->
        raise AssumptionFailed, message: "Strategy is missing from the changeset context."
    end
  end

  defp do_change(changeset, strategy) do
    changeset
    |> Changeset.before_action(fn changeset ->
      with token when is_binary(token) <- Changeset.get_argument(changeset, :confirm),
           {:ok, %{"act" => action, "chg" => changes}, _} <-
             Jwt.verify(token, changeset.resource),
           true <- to_string(strategy.confirm_action_name) == action do
        allowed_changes =
          if strategy.inhibit_updates?,
            do: Map.take(changes, Enum.map(strategy.monitor_fields, &to_string/1)),
            else: %{}

        changeset
        |> Changeset.change_attributes(allowed_changes)
        |> Changeset.change_attribute(strategy.confirmed_at_field, DateTime.utc_now())
      else
        _ ->
          raise InvalidArgument, field: :confirm, message: "is not valid"
      end
    end)
  end
end
