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

    if is_nil(identity) do
      Query.filter(query, false)
    else
      Query.filter(query, ^ref(identity_field) == ^identity)
    end
    |> Query.before_action(fn query ->
      query
      |> Ash.Query.ensure_selected(select_for_senders)
      |> Ash.Query.ensure_selected([identity_field])
    end)
    |> Query.after_action(&after_action(&1, &2, strategy, identity))
  end

  defp after_action(_query, [user], %{sender: {sender, send_opts}} = strategy, _identity) do
    case MagicLink.request_token_for(strategy, user) do
      {:ok, token} -> sender.send(user, token, send_opts)
      _ -> nil
    end

    {:ok, []}
  end

  defp after_action(
         _query,
         _,
         %{registration_enabled?: true, sender: {sender, send_opts}} = strategy,
         identity
       )
       when not is_nil(identity) do
    case MagicLink.request_token_for_identity(strategy, identity) do
      {:ok, token} -> sender.send(to_string(identity), token, send_opts)
      _ -> nil
    end

    {:ok, []}
  end

  defp after_action(_, _, _, _) do
    {:ok, []}
  end
end
