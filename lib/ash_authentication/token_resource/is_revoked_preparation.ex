defmodule AshAuthentication.TokenResource.IsRevokedPreparation do
  @moduledoc """
  Constrains a query to only records which are revocations that match the token
  or jti argument.
  """

  use Ash.Resource.Preparation
  alias Ash.{Query, Resource.Preparation}
  alias AshAuthentication.Jwt
  require Ash.Query

  @doc false
  @impl true
  @spec prepare(Query.t(), keyword, Preparation.Context.t()) :: Query.t()
  def prepare(query, _opts, _context) do
    case get_jti(query) do
      {:ok, jti} ->
        query
        |> Query.filter(purpose: "revocation", jti: jti)
        |> Query.limit(1)

      :error ->
        Query.limit(query, 0)
    end
  end

  defp get_jti(query) do
    [:jti, :token]
    |> Stream.map(&{&1, Query.get_argument(query, &1)})
    |> Stream.filter(&elem(&1, 1))
    |> Enum.reduce_while(:error, fn
      {:jti, jti}, _ ->
        {:halt, {:ok, jti}}

      {:token, token}, _ ->
        case Jwt.peek(token) do
          {:ok, %{"jti" => jti}} -> {:halt, {:ok, jti}}
          _ -> {:cont, :error}
        end
    end)
  end
end
