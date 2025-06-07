defmodule AshAuthentication.Strategy.RememberMe.MaybeGenerateTokenPreparation do
  @moduledoc """
  Maybe generate a remember me token and put it in the metadata of the resource to
  later be dropped as a cookie.
  """
  use Ash.Resource.Preparation
  # alias AshAuthentication.{Errors.AuthenticationFailed, Info, Jwt, TokenResource}
  # alias Ash.{Error.Unknown, Query, Resource, Resource.Preparation}
  # require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, _options, _context) do
    query
  end

end
