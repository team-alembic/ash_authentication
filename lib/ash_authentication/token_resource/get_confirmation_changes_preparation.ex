defmodule AshAuthentication.TokenResource.GetConfirmationChangesPreparation do
  @moduledoc """
  Constrains a query to only records which are confirmations that match the jti
  argument.
  """

  use Ash.Resource.Preparation
  alias Ash.{Query, Resource.Preparation}
  alias AshAuthentication.Strategy
  require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, _, _) do
    jti = Query.get_argument(query, :jti)
    strategy = query.context.strategy

    query
    |> Query.filter(purpose: to_string(Strategy.name(strategy)), jti: jti)
    |> Query.filter(expires_at >= now())
  end
end
