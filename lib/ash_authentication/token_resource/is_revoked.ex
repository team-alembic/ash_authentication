defmodule AshAuthentication.TokenResource.IsRevoked do
  @moduledoc """
  Checks for the existence of a revocation token for the provided tokenrevocation token for the provided token.
  """
  use Ash.Resource.Actions.Implementation

  @impl true
  def run(input, _, _) do
    input.resource
    |> Ash.Query.do_filter(purpose: "revocation", jti: input.arguments.jti)
    |> Ash.exists()
  end
end
