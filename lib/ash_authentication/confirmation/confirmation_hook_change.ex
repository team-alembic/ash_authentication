defmodule AshAuthentication.Confirmation.ConfirmationHookChange do
  @moduledoc """
  Triggers a confirmation flow when one of the monitored fields is changed.

  Optionally inhibits changes to monitored fields on update.
  """

  use Ash.Resource.Change
  alias AshAuthentication.{Confirmation, Confirmation.Info}
  alias Ash.{Changeset, Resource.Change}

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.context()) :: Changeset.t()
  def change(changeset, _opts, _context) do
    changeset
    |> Changeset.before_action(fn changeset ->
      options = Info.options(changeset.resource)

      changeset
      |> not_confirm_action(options)
      |> should_confirm_action_type(options)
      |> monitored_field_changing(options)
      |> changes_would_be_valid()
      |> maybe_inhibit_updates(options)
      |> maybe_perform_confirmation(options, changeset)
    end)
  end

  defp not_confirm_action(changeset, options)
       when changeset.action != options.confirm_action_name,
       do: changeset

  defp not_confirm_action(_changeset, _options), do: nil

  defp should_confirm_action_type(changeset, options)
       when changeset.action_type == :create and options.confirm_on_create?,
       do: changeset

  defp should_confirm_action_type(changeset, options)
       when changeset.action_type == :update and options.confirm_on_update?,
       do: changeset

  defp should_confirm_action_type(_changeset, _options), do: nil

  defp monitored_field_changing(nil, _options), do: nil

  defp monitored_field_changing(changeset, options) do
    if Enum.any?(options.monitor_fields, &Changeset.changing_attribute?(changeset, &1)),
      do: changeset,
      else: nil
  end

  defp changes_would_be_valid(changeset) when changeset.valid?, do: changeset
  defp changes_would_be_valid(_), do: nil

  defp maybe_inhibit_updates(changeset, options)
       when changeset.action_type == :update and options.inhibit_updates? do
    options.monitor_fields
    |> Enum.reduce(changeset, &Changeset.clear_change(&2, &1))
  end

  defp maybe_inhibit_updates(changeset, _options), do: changeset

  defp maybe_perform_confirmation(nil, _options, original_changeset), do: original_changeset

  defp maybe_perform_confirmation(changeset, options, original_changeset) do
    changeset
    |> Changeset.after_action(fn _changeset, user ->
      original_changeset
      |> Confirmation.confirmation_token_for(user)
      |> case do
        {:ok, token} ->
          {sender, send_opts} = options.sender
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
end
