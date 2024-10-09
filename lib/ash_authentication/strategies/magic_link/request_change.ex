defmodule AshAuthentication.Strategy.MagicLink.RequestChange do
  @moduledoc """
  Setup a changeset for a magic link request.

  This sends an upserted user their magic link token.
  """
  use Ash.Resource.Change
  alias Ash.{Changeset, Resource.Change}
  alias AshAuthentication.{Info, Strategy.MagicLink}

  @doc false
  @impl true
  @spec change(Changeset.t(), keyword, Change.Context.t()) :: Changeset.t()
  def change(changeset, _opts, _context) do
    strategy = Info.strategy_for_action!(changeset.resource, changeset.action.name)

    identity_field = strategy.identity_field

    identity =
      Changeset.get_attribute(changeset, identity_field)

    select_for_senders = Info.authentication_select_for_senders!(changeset.resource)

    if is_nil(identity) do
      changeset
    else
      changeset
      |> Changeset.force_change_attribute(identity_field, identity)
      |> Changeset.ensure_selected(select_for_senders)
      |> Changeset.after_action(&after_action(&1, &2, strategy))
    end
  end

  defp after_action(_query, user, %{sender: {sender, send_opts}} = strategy) do
    with {:ok, token} <- MagicLink.request_token_for(strategy, user) do
      sender.send(user, token, send_opts)
    end

    {:ok, user}
  end

  defp after_action(_, user, _), do: {:ok, user}
end
