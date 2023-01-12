defmodule AshAuthentication.AddOn.Confirmation.ConfirmationHookChange do
  @moduledoc """
  Triggers a confirmation flow when one of the monitored fields is changed.

  Optionally inhibits changes to monitored fields on update.
  """

  use Ash.Resource.Change
  alias Ash.{Changeset, Resource.Change}
  alias AshAuthentication.{AddOn.Confirmation, Info}

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, _context) do
    case Info.strategy(changeset.resource, :confirm) do
      {:ok, strategy} ->
        do_change(changeset, strategy)

      :error ->
        changeset
    end
  end

  defp do_change(changeset, strategy) do
    changeset
    |> Changeset.before_action(fn changeset ->
      changeset
      |> not_confirm_action(strategy)
      |> should_confirm_action_type(strategy)
      |> monitored_field_changing(strategy)
      |> changes_would_be_valid()
      |> maybe_inhibit_updates(strategy)
      |> maybe_perform_confirmation(strategy, changeset)
    end)
  end

  defp not_confirm_action(%Changeset{} = changeset, strategy)
       when changeset.action != strategy.confirm_action_name,
       do: changeset

  defp not_confirm_action(_changeset, _strategy), do: nil

  defp should_confirm_action_type(%Changeset{} = changeset, strategy)
       when changeset.action_type == :create and strategy.confirm_on_create?,
       do: changeset

  defp should_confirm_action_type(%Changeset{} = changeset, strategy)
       when changeset.action_type == :update and strategy.confirm_on_update?,
       do: changeset

  defp should_confirm_action_type(_changeset, _strategy), do: nil

  defp monitored_field_changing(%Changeset{} = changeset, strategy) do
    if Enum.any?(strategy.monitor_fields, &Changeset.changing_attribute?(changeset, &1)),
      do: changeset,
      else: nil
  end

  defp monitored_field_changing(_changeset, _strategy), do: nil

  defp changes_would_be_valid(%Changeset{} = changeset) when changeset.valid?, do: changeset
  defp changes_would_be_valid(_), do: nil

  defp maybe_inhibit_updates(%Changeset{} = changeset, strategy)
       when changeset.action_type == :update and strategy.inhibit_updates? do
    strategy.monitor_fields
    |> Enum.reduce(changeset, &Changeset.clear_change(&2, &1))
  end

  defp maybe_inhibit_updates(changeset, _strategy), do: changeset

  defp maybe_perform_confirmation(%Changeset{} = changeset, strategy, original_changeset) do
    changeset
    |> Changeset.after_action(fn _changeset, user ->
      strategy
      |> Confirmation.confirmation_token(original_changeset, user)
      |> case do
        {:ok, token} ->
          {sender, send_opts} = strategy.sender
          sender.send(user, token, send_opts)

          metadata =
            user.__metadata__
            |> Map.put(:confirmation_token, token)

          {:ok, %{user | __metadata__: metadata}}

        _ ->
          {:ok, user}
      end
    end)
  end

  defp maybe_perform_confirmation(_changeset, _strategy, original_changeset),
    do: original_changeset
end
