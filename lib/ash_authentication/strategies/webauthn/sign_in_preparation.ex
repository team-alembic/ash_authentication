defmodule AshAuthentication.Strategy.WebAuthn.SignInPreparation do
  @moduledoc """
  Prepare a query for WebAuthn sign in.

  Constrains the query to match the identity field passed to the action.
  Unlike the Password strategy's SignInPreparation, this module does NOT
  handle credential verification or token generation - those happen in
  the Actions module after Wax assertion verification.
  """
  use Ash.Resource.Preparation
  alias Ash.{Query, Resource.Preparation}
  alias AshAuthentication.Info
  require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, options, context) do
    {:ok, strategy} = Info.find_strategy(query, context, options)
    identity_field = strategy.identity_field
    identity = Query.get_argument(query, identity_field)

    if is_nil(identity) do
      Query.filter(query, false)
    else
      Query.filter(query, ^ref(identity_field) == ^identity)
    end
  end
end
