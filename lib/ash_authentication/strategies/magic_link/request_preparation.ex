defmodule AshAuthentication.Strategy.MagicLink.RequestPreparation do
  @moduledoc """
  Prepare a query for a magic link request.

  This preparation performs three jobs, one before the query executes and two
  after:
  1. it constraints the query to match the identity field passed to the action.
  2. if there is a user returned by the query, then
    a. generate a magic link token and
    b. publish a notification.

  Always returns an empty result.
  """
  use Ash.Resource.Preparation
  alias Ash.{Query, Resource.Preparation}
  alias AshAuthentication.{Info, Strategy.MagicLink}
  require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, _opts, _context) do
    strategy = Info.strategy_for_action!(query.resource, query.action.name)

    identity_field = strategy.identity_field
    identity = Query.get_argument(query, identity_field)
    select_for_senders = Info.authentication_select_for_senders!(query.resource)

    query
    |> Query.filter(^ref(identity_field) == ^identity)
    |> Query.before_action(fn query ->
      Ash.Query.ensure_selected(query, select_for_senders)
    end)
    |> Query.after_action(&after_action(&1, &2, strategy))
  end

  defp after_action(_query, [user], %{sender: {sender, send_opts}} = strategy) do
    case MagicLink.request_token_for(strategy, user) do
      {:ok, token} -> sender.send(user, token, send_opts)
      _ -> nil
    end

    {:ok, []}
  end

  defp after_action(_, _, _), do: {:ok, []}
end
