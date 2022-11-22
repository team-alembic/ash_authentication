defmodule AshAuthentication.Strategy.Password.RequestPasswordResetPreparation do
  @moduledoc """
  Prepare a query for a password reset request.
  This preparation performs three jobs, one before the query executes and two
  after.
  Firstly, it constraints the query to match the identity field passed to the
  action.
  Secondly, if there is a user returned by the query, then generate a reset
  token and publish a notification.  Always returns an empty result.
  """
  use Ash.Resource.Preparation
  alias Ash.{Query, Resource.Preparation}
  alias AshAuthentication.Strategy.Password
  require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.context()) :: Query.t()
  def prepare(query, _opts, _context) do
    strategy = Map.fetch!(query.context, :strategy)

    if Enum.any?(strategy.resettable) do
      identity_field = strategy.identity_field
      identity = Query.get_argument(query, identity_field)

      query
      |> Query.filter(ref(^identity_field) == ^identity)
      |> Query.after_action(&after_action(&1, &2, strategy))
    else
      query
    end
  end

  defp after_action(_query, [user], %{resettable: [%{sender: {sender, send_opts}}]} = strategy) do
    case Password.reset_token_for(strategy, user) do
      {:ok, token} -> sender.send(user, token, send_opts)
      _ -> nil
    end

    {:ok, []}
  end

  defp after_action(_query, _, _), do: {:ok, []}
end
